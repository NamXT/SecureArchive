### SECURITY Policy — SecureArchive / TitanCrypt Engine

## 1. Threat Model

SecureArchive is designed for high‑security, offline environments and follows a conservative, defensive threat model.

### 1.1. Relevant Threat Actors
- Unauthorized internal users (insider threats)
- External attackers (opportunistic and targeted)
- Forensic analysts with extended read access
- Post‑breach attackers with device access

### 1.2. Attacks Mitigated
- Offline brute‑force attempts
- Container manipulation or tampering
- Replay / injection attacks against metadata
- Partial extraction of encrypted blocks
- Forensic analysis of file offsets or metadata

### 1.3. Out of Scope
SecureArchive does not protect against:
- Keylogging or memory sniffing on compromised systems
- Weak user passwords
- Social engineering
- Loss of the password (zero‑knowledge model)

<br>

## 2. Cryptographic Decisions

### 2.1. Encryption
- AES‑256‑GCM authenticated encryption
- Full payload authentication
- No legacy modes such as CBC or CTR

### 2.2. Key Derivation
- PBKDF2‑SHA512
- Default: 300,000 iterations
- 16‑byte random salt

### 2.3. Key Handling
- Keys exist only in RAM
- Wiped immediately after use
- Never logged or transmitted

### 2.4. Design Principles
- Zero‑knowledge architecture
- Minimal external dependencies
- No debug keys or bypass paths

<br>

## 3. Integrity Mechanisms

### 3.1. GCM Authentication
- Authenticated AAD: SECARC01 magic header
- 128‑bit GCM authentication tag
- Ensures manifest + payload integrity

### 3.2. Manifest Protection
- Fully encrypted manifest
- No plaintext metadata
- Any tampering triggers failure

### 3.3. Version Safety
- Version mismatch triggers strict rejection
- No fallback to weakened formats

<br>

## 4. Password Handling

### 4.1. No Storage
- Passwords are never stored
- No telemetry, logs, or caching

### 4.2. Runtime Behavior
- Password used only for KDF
- Immediately wiped after use

### 4.3. User Recommendations
- Minimum length: 12+ characters
- Recommended: 16–24 characters
- Mix of uppercase/lowercase letters, digits, symbols
- Use password rotation for long‑term archives

<br>

## 5. Security Policies

### 5.1. Principles
- Offline‑only operation
- Defense‑in‑depth
- Zero trust for external systems
- Minimal attack surface

### 5.2. Development Rules
- No sensitive debug output
- Strict input validation
- Clear security exception hierarchy
- Routine dependency reviews

### 5.3. Storage & Transport
- `.secarc` contains only encrypted content
- No plaintext metadata outside manifest
- Manifest parsed only post‑decryption

### 5.4. Security Updates
- Cryptographic primitives reviewed routinely
- Backwards compatibility deliberately limited
- New container versions introduced as needed
