### ARCHITECTURE.md — SecureArchive / TitanCrypt Engine

## 1. Overview

SecureArchive is built on a modular, layered architecture designed for security, clarity, and long-term maintainability.  
The system separates cryptographic operations, container logic, filesystem processing, and user interfaces into distinct components.

This ensures:
- Clear security boundaries  
- Minimal attack surface  
- Extensibility for future container formats  
- Clean separation between engine, CLI, and GUI  

<br>

## 2. Layered Architecture

```
┌──────────────────────────────────────────────────────┐
│                     GUI Layer (PySide6)              │
│  - User Interface for encryption/decryption          │
│  - Error dialogs, file pickers, progress UI          │
└──────────────────────────────────────────────────────┘
               ▲
               │
┌──────────────────────────────────────────────────────┐
│                      CLI Layer                       │
│  - Command-line interface                            │
│  - Scriptable automation                             │
└──────────────────────────────────────────────────────┘
               ▲
               │
┌──────────────────────────────────────────────────────┐
│                SecureArchive Engine (Core)           │
│  - Container creation                                │
│  - Encryption & decryption pipeline                  │
│  - Manifest handling                                 │
│  - Offset/length mapping                             │
└──────────────────────────────────────────────────────┘
               ▲
               │
┌──────────────────────────────────────────────────────┐
│                 Crypto Primitive Layer               │
│  - AES-256-GCM                                       │
│  - PBKDF2-SHA512                                     │
│  - Salt/nonce generation                             │
└──────────────────────────────────────────────────────┘
               ▲
               │
┌──────────────────────────────────────────────────────┐
│                 Filesystem Utility Layer             │
│  - Recursive folder scanning                         │
│  - Metadata extraction                               │
│  - File entry modeling                               │
└──────────────────────────────────────────────────────┘
```

<br>

## 3. Core Components

### 3.1. Engine (`engine.py`)
The TitanCrypt Engine coordinates the complete container lifecycle:

**Responsibilities:**
- Build container header  
- Construct encrypted manifest  
- Concatenate raw file payloads  
- Encrypt final payload using AES-GCM  
- Verify container integrity  
- Extract files from decrypted payload  
- Manage password changes  

**Outputs:**
- `.secarc` binary file  


### 3.2. Crypto Module (`crypto.py`)

**Functions:**
- `derive_key()` → PBKDF2-SHA512  
- `generate_salt()`  
- `encrypt_aes_gcm()`  
- `decrypt_aes_gcm()`  

This layer includes *no* application logic.  
It is deterministic, self-contained, and easily testable.


### 3.3. Filesystem Utility (`fsutil.py`)

Handles traversal and mapping of input directories.

**Provides:**
- FileEntry dataclass  
- Recursive directory walkthrough  
- Size and timestamp metadata  
- Path normalization (relative/absolute)  


### 3.4. Internationalization (`i18n.py`)
Keeps GUI and CLI bilingual (EN/DE).

**Features:**
- Central translation dictionary  
- Runtime selection  
- Human-friendly keys  


### 3.5. GUI (`securearchive_gui.py`)
Built with PySide6.

**Responsibilities:**
- User interaction  
- Password prompts  
- File selection  
- Visual error handling  
- Success notifications  


### 3.6. CLI (`securearchive_main.py`)
Provides terminal access.

**Supports:**
- container creation  
- extraction  
- listing  
- verification  
- password rotation  

<br>

## 4. Data Flow Architecture

### 4.1. Encryption Flow

```
[Folder] → fsutil → FileEntry list
           │
           ▼
     Manifest builder
           │
           ▼
[manifest.json + data payload]
           │
           ▼
AES-GCM Encryption → [ciphertext]
           │
           ▼
Header builder → [header bytes]
           │
           ▼
Write .secarc container
```

<br>

### 4.2. Decryption Flow

```
Load file → parse header → derive key
           │
           ▼
AES-GCM decryption → plaintext
           │
           ▼
Split manifest + data payload
           │
           ▼
Reconstruct file tree on output path
```

<br>

## 5. Internal Data Structures

### 5.1. Header Structure
```
MAGIC (8 bytes)
VERSION (1 byte)
Salt length (1 byte)
Salt (variable)
Iterations (4 bytes)
Nonce length (1 byte)
Nonce (variable)
```

### 5.2. Manifest Structure
Stored as UTF‑8 JSON inside encrypted payload.

```
{
  "version": 1,
  "cipher": "AES-256-GCM",
  "kdf": {
      "type": "PBKDF2-SHA512",
      "iterations": 300000,
      "salt_hex": "..."
  },
  "root": "/absolute/path",
  "entries": [
      {
        "path": "relative/file/path",
        "size": 12345,
        "mtime": 1700000000,
        "offset": 0,
        "length": 12345
      }
  ]
}
```

<br>

## 6. Design Principles

- Zero-knowledge cryptographic model  
- No plaintext metadata  
- 100% offline, no network stack  
- Strict separation of concerns  
- Predictable versioning  
- Testable core components  
- Fail-fast error handling  


## 7. Roadmap for Version 2

### Planned:
- Block‑based container format  
- Parallelized encryption / decryption  
- Header v2 with extended metadata  
- Hardware key support (FIDO2 / WebAuthn)  
- Optional compression layer  
