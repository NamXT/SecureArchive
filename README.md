
<!-- <p align="center">
  <img src="docs/assets/securearchive_logo.svg" width="260" />
</p>
<p align="center">
  Powered by the TitanCrypt Engine · Developed by BYLICKILABS
</p>
-->

<p align="center">

  <img src="https://img.shields.io/github/actions/workflow/status/bylickilabs/SecureArchive/securearchive-ci.yml?branch=main&label=Build&logo=github">
  <img src="https://img.shields.io/badge/Python-3.12+-blue?logo=python">
  <img src="https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20macOS-blueviolet">

  <br>

  <img src="https://img.shields.io/badge/Crypto%20Engine-TitanCrypt%20Core%20v1.0-9cf">
  <img src="https://img.shields.io/badge/Security-AES--256--GCM%20%7C%20PBKDF2--SHA512-orange">
  <img src="https://img.shields.io/badge/Integrity-GCM--Auth--Tag-critical">
  <img src="https://img.shields.io/badge/Container-.secarc%20Custom-0aa">

  <br>

  <img src="https://img.shields.io/badge/GUI-PySide6-blue?logo=qt">
  <img src="https://img.shields.io/badge/CLI-Full%20Support-success">
  <img src="https://img.shields.io/badge/Dependencies-PySide6%20%7C%20Cryptography-green">

  <br>

  <img src="https://img.shields.io/badge/Mode-Offline--Only-important">
  <img src="https://img.shields.io/badge/Version-1.0.0-brightgreen">
  <img src="https://img.shields.io/badge/License-MIT-red">

</p>

|SecureArchive | [![SecureArchive CI](https://github.com/bylickilabs/SecureArchive/actions/workflows/securearchive-ci.yml/badge.svg)](https://github.com/bylickilabs/SecureArchive/actions/workflows/securearchive-ci.yml) |
|---|---|

<br>

> Modern file and folder encryption powered by the TitanCrypt Engine

| <img width="1274" height="354" alt="image" src="https://github.com/user-attachments/assets/3eb23ef0-105f-4cf1-bce7-14a5caade6ac" /> |
|---|

<br>

---

<br>

| <img width="1280" height="640" alt="1" src="https://github.com/user-attachments/assets/92ced5cf-dc27-41ec-bb64-a5f524fd9f6f" /> | <img width="1280" height="640" alt="4" src="https://github.com/user-attachments/assets/ee4b80c8-e89f-410d-b639-1482b25967c3" /> |
|---|---|

| <img width="1280" height="640" alt="514142180-0d214464-654b-42dc-8c97-3ec91d93e524" src="https://github.com/user-attachments/assets/de4d3dce-d53d-43e0-bfb7-cf9c1e396d1c" /> |
|---|

SecureArchive is a standalone, fully offline application for securely encrypting files and directory structures. It uses a proprietary container format (.secarc) and the custom-built TitanCrypt Engine.

## Features
- AES-256-GCM encryption  
- PBKDF2-SHA-512 key derivation  
- Custom .secarc container format  
- Fully encrypted manifest  
- GUI + CLI  
- Password rotation  
- Integrity verification  
- Bilingual (EN/DE)

## Installation
python -m venv .venv  
source .venv/bin/activate
pip install -r requirements.txt  

## Start GUI
python securearchive_gui.py

```yarn
SecureArchive/
│
├── securearchive/
│   ├── engine.py
│   ├── crypto.py
│   ├── fsutil.py
│   ├── i18n.py
│   ├── errors.py
│   └── __init__.py
│
├── securearchive_gui.py
├── securearchive_main.py
├── requirements.txt
├── README.md
└── LICENSE.md
```
