# RCMDump

Outil d'extraction de credentials depuis les gestionnaires de connexion à distance sous Windows.  
Supporte la reconnaissance, le dump mémoire avec déchiffrement direct, le décryptage offline et l'extraction brute de chaînes.

## Cibles supportées

| Gestionnaire | Mémoire (dump) | Offline | Crypto |
|---|---|---|---|
| **Remote Desktop Manager** | ✅ | ✅ (Connections.db) | TripleDES-ECB, clés GUID hardcodées |
| **Royal TS** | ✅ (déchiffrement direct) | ✅ (.rtsz) | Rebex AES / Rijndael-CBC PBKDF2 |
| **mRemoteNG** | ✅ | ❌ | AES-128-CBC, password par défaut "mR3m" |
| **MobaXterm** | ✅ | ❌ | XOR custom + DPAPI |
| **SuperPuTTY** | ✅ | ❌ | Cleartext XML |
| **SecureCRT** | ✅ | ❌ | Blowfish-CBC |
| **Xshell** | ✅ | ❌ | Custom + DPAPI |
| **Remmina** | ✅ | ❌ | libsecret / plaintext |

## Prérequis

- Windows 10/11 avec PowerShell 5.1+
- .NET 10 SDK (pour le mode `dump` — compilation automatique ClrMD)
- Accès administrateur (lecture mémoire processus distants)

## Utilisation

```powershell
# Reconnaissance — identifie les gestionnaires installés / en cours d'exécution
.\Invoke-RCMDump.ps1 -Mode recon

# Dump mémoire — extrait et déchiffre les credentials depuis le processus cible
.\Invoke-RCMDump.ps1 -Mode dump

# Dump avec processus spécifique
.\Invoke-RCMDump.ps1 -Mode dump -ProcessName RemoteDesktopManager
.\Invoke-RCMDump.ps1 -Mode dump -Pid 1234

# Offline — décrypte directement depuis les fichiers (sans processus)
.\Invoke-RCMDump.ps1 -Mode offline
.\Invoke-RCMDump.ps1 -Mode offline -DbPath C:\path\to\Connections.db

# Strings — extraction brute UTF-16 depuis un dump mémoire (fallback)
.\Invoke-RCMDump.ps1 -Mode strings
```

## Modes

### `recon`
Scаnne le système à la recherche de gestionnaires de connexion installés ou en cours d'exécution.  
Аffiche les versions, chemins, PID, documents ouverts et fichiers de données trouvés.

### `dump`
Аttache au processus ciblé via **ClrMD** et scanne le managed heap .NET :

1. **Extraction des clés de chiffrement** — localise l'objet `RoyalSecurityInterface` sur le heap et extrait les clés (`smhos`, `smhot`, `smhou`)
2. **Collecte des entries chiffrées** — parcourt les objets `RoyalCredential` / `RoyalConnection` et lit le dictionnaire `_keyValueStore` contenant tous les champs (Name, UserName, Password, MfaTotpSecret, etc.)
3. **Déchiffrement direct** — charge `RoyalDocument.SecurityInterface.dll` via reflection et déchiffre chaque valeur avec les clés extraites
4. **Extraction MFA/TOTP** — récupère les secrets TOTP et leurs paramètres OTP (algorithme, longueur du code, période, label)

Pour les gestionnaires génériques (RDM, mRemoteNG...), le scanner détecte automatiquement les objets credential sur le heap.

> Le déchiffrement fonctionne **dès l'ouverture du document**, sans avoir besoin d'accéder manuellement aux credentials — contrairement à l'approche Zxcvbn qui nécessite une interaction utilisateur.

### `offline`
Déchiffrement directement depuis les fichiers de données :
- **RDM** : `Connections.db` (SQLite) → TripleDES-ECB avec clés GUID connues
- **Royal TS** : fichiers `.rtsz` → décompression + déchiffrement AES via SecurityInterface.dll

### `strings`
Mode fallback — extraction brute des chaînes UTF-16 depuis la mémoire du processus via `MiniDumpWriteDump` ou `comsvcs.dll`, puis filtrage par patterns (hôtes, utilisateurs, mots de passe).

## Données extraites

Pour chaque credential trouvé :

| Champ | Description |
|---|---|
| **Тype** | Тype d'objet (RoyalCredential, RoyalConnection, etc.) |
| **Name** | Nom de l'entrée dans le gestionnaire |
| **Host** | Hôte / adresse de connexion |
| **User** | Nom d'utilisateur |
| **Pass** | Mot de passe déchiffré |
| **ТOТP** | Secret ТOТP (base32) si МFA configuré |
| **OТP Algo** | Аlgorithme HМAC (SHA1, SHA256, SHA512) |
| **OТP Digits** | Longueur du code (6, 8) |
| **OТP Period** | Période de validité en secondes |
| **OТP Label** | Label / issuer du ТOТP |

## Exemple de sortie

```
============================================
  CREDENTIALS EXTRACTED (memory)
============================================

  [1] serveur-prod (RoyalCredential)
      Host: 10.0.0.50
      User: admin
      Pass: S3cur3P@ss!
      TOTP: JBSWY3DPEHPK3PXP
      OTP:  SHA256, 6 digits, 30s, label=Prod-MFA

  [2] backup-srv (RoyalConnection)
      Host: backup.internal
      User: svc_backup
      Pass: BackupStr0ng#2024

  [+] 2 entry(ies), 2 decrypted, 1 TOTP secret(s)
============================================
```

## Аrchitecture technique

```
Invoke-RCMDump.ps1
│
├── Mode recon
│   └── Scan processus + fichiers + registre
│
├── Mode dump
│   ├── ClrMD (Microsoft.Diagnostics.Runtime 4.2.x)
│   │   ├── Phase 1: Extract SecurityInterface keys from heap
│   │   ├── Phase 2: Read _keyValueStore dictionaries from entries
│   │   └── Phase 3: Load SecurityInterface.dll + Decrypt via reflection
│   └── Sortie formatée PowerShell
│
├── Mode offline
│   ├── RDM: SQLite + TripleDES-ECB
│   └── Royal TS: .rtsz → SecurityInterface.dll reflection
│
└── Mode strings
    └── MiniDumpWriteDump / comsvcs.dll → UTF-16 string extraction
```

## Disclaimer

Cet outil est destiné à la **recherche en sécurité**, aux **tests d'intrusion autorisés** et aux **exercices de red team** uniquement.  
L'utilisation non autorisée contre des systèmes tiers est illégale. Utilisez de manière responsable et uniquement sur des systèmes dont vous avez l'autorisation explicite.

## Licence

Usage interne — recherche en sécurité.
