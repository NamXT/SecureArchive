# CHANGELOG.md — SecureArchive / TitanCrypt Engine

All notable changes to this project will be documented in this file.  
This project adheres to **semantic versioning** and maintains a clear, auditable history of engine, GUI, and container-format changes.

---

## [1.0.0] — 2025-11-13
### 🚀 Initial Stable Release (TitanCrypt Engine v1)
- Introduced the **SecureArchive** offline encryption suite  
- Added **TitanCrypt Engine v1.0**  
- Implemented **AES‑256‑GCM** encryption pipeline  
- Added **PBKDF2‑SHA512** key derivation  
- Introduced **.secarc container format v1**  
- Implemented full **manifest encryption**  
- Added **payload separator** architecture  
- Added dynamic salt & nonce generation  
- Fully implemented **password‑based encryption**  
- Added **integrity validation** using GCM authentication tag  
- Implemented **password rotation** with re-encryption  
- Added container verification routine  
- Implemented recursive directory collection (fsutil)  
- Added **GUI (PySide6)** for encryption & extraction  
- Added **CLI tool** for automated workflows  
- Added bilingual interface (EN/DE)  
- Implemented exception hierarchy (SecureArchiveError, InvalidContainerError, WrongPasswordError)
