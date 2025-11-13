# SecureArchive  
Modern file and folder encryption powered by the TitanCrypt Engine

| <img width="1280" height="640" alt="1" src="https://github.com/user-attachments/assets/92ced5cf-dc27-41ec-bb64-a5f524fd9f6f" /> | <img width="1280" height="640" alt="4" src="https://github.com/user-attachments/assets/ee4b80c8-e89f-410d-b639-1482b25967c3" /> |
|---|---|

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

SecureArchive/
│
├── securearchive/
│   ├── engine.py           # TitanCrypt Engine
│   ├── crypto.py           # AES-GCM, PBKDF2
│   ├── fsutil.py           # Datei- und Ordnerverarbeitung
│   ├── i18n.py             # Sprachsystem
│   ├── errors.py           # Fehlerklassen
│   └── __init__.py
│
├── securearchive_gui.py    # PySide6 eGUI
├── securearchive_main.py   # CLI
├── requirements.txt
├── README.md
└── LICENSE.md

