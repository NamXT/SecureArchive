from typing import Dict


I18N: Dict[str, Dict[str, str]] = {
    "en": {
        "common.error": "Error",
        "common.done": "Done.",
        "common.language_set": "Language set to English.",

        "password.prompt": "Enter password: ",
        "password.prompt_confirm": "Confirm password: ",
        "password.mismatch": "Passwords do not match.",
        "password.current": "Enter current password: ",
        "password.new": "Enter new password: ",
        "password.new_confirm": "Confirm new password: ",

        "encrypt.start": "Starting encryption...",
        "encrypt.success": "Encryption completed successfully.",
        "encrypt.overwrite_blocked": "Output file already exists. Use --force to overwrite.",
        "encrypt.source_missing": "Input path does not exist.",
        "decrypt.start": "Starting decryption...",
        "decrypt.success": "Decryption completed successfully.",
        "list.start": "Reading container...",
        "list.header": "Container contents:",
        "list.entry": "{path} ({size} bytes)",
        "verify.start": "Verifying container integrity...",
        "verify.success": "Container integrity verified successfully.",
        "verify.failure": "Container integrity check failed.",
        "passwd.success": "Password changed successfully.",
        "error.invalid_container": "Invalid or unsupported container format.",
        "error.wrong_password": "Decryption failed – possibly wrong password or corrupted data.",
        "error.io": "I/O error occurred.",
        "error.generic": "Unexpected error occurred.",

        "cli.description": "SecureArchive Engine – encrypt and decrypt files and directories.",
        "cli.lang_help": "Language for CLI messages (en/de).",
        "cli.cmd.encrypt": "Encrypt files and directories / Dateien und Verzeichnisse verschlüsseln.",
        "cli.cmd.decrypt": "Decrypt a container / Container entschlüsseln.",
        "cli.cmd.list": "List container contents / Container-Inhalt anzeigen.",
        "cli.cmd.verify": "Verify container integrity / Container-Integrität prüfen.",
        "cli.cmd.passwd": "Change container password / Container-Passwort ändern.",
        "cli.arg.input": "Input file or directory / Eingabedatei oder Verzeichnis.",
        "cli.arg.output": "Output container file / Ausgabedatei (Container).",
        "cli.arg.container": "Container file / Container-Datei.",
        "cli.arg.output_dir": "Output directory / Ausgabe-Verzeichnis.",
        "cli.arg.force": "Overwrite existing output file / Bestehende Ausgabedatei überschreiben.",
        "cli.arg.iterations": "PBKDF2 iterations for key derivation.",

        "gui.title": "SecureArchive – File & Folder Encryption",
        "gui.lang.de": "Deutsch",
        "gui.lang.en": "English",
        "gui.status.ready": "Ready.",
        "gui.status.running": "Operation running...",
        "gui.status.done": "Operation finished.",
        "gui.status.error": "Operation failed.",
        "gui.button.browse_file": "Browse file...",
        "gui.button.browse_folder": "Browse folder...",
        "gui.button.browse_container": "Select container...",
        "gui.button.browse_output_dir": "Select output folder...",

        "gui.tab.encrypt": "Encrypt",
        "gui.tab.decrypt": "Decrypt",
        "gui.tab.list": "List",
        "gui.tab.verify": "Verify",
        "gui.tab.passwd": "Change Password",

        "gui.encrypt.input_label": "Input (file or folder):",
        "gui.encrypt.output_label": "Output container file:",
        "gui.encrypt.password_label": "Password:",
        "gui.encrypt.password_confirm_label": "Confirm password:",
        "gui.encrypt.iterations_label": "PBKDF2 iterations:",
        "gui.encrypt.force_label": "Overwrite existing container",
        "gui.encrypt.button": "Encrypt",

        "gui.decrypt.container_label": "Container file:",
        "gui.decrypt.output_dir_label": "Output directory:",
        "gui.decrypt.password_label": "Password:",
        "gui.decrypt.button": "Decrypt",

        "gui.list.container_label": "Container file:",
        "gui.list.password_label": "Password:",
        "gui.list.button": "List contents",

        "gui.verify.container_label": "Container file:",
        "gui.verify.password_label": "Password:",
        "gui.verify.button": "Verify",

        "gui.passwd.container_label": "Container file:",
        "gui.passwd.current_label": "Current password:",
        "gui.passwd.new_label": "New password:",
        "gui.passwd.new_confirm_label": "Confirm new password:",
        "gui.passwd.iterations_label": "PBKDF2 iterations (optional):",
        "gui.passwd.button": "Change password",

        "gui.msg.encrypt.success": "Encryption completed successfully.",
        "gui.msg.decrypt.success": "Decryption completed successfully.",
        "gui.msg.list.success": "Listed container contents.",
        "gui.msg.verify.success": "Container integrity verified successfully.",
        "gui.msg.verify.failure": "Container integrity check failed.",
        "gui.msg.passwd.success": "Password changed successfully.",
        "gui.msg.error.missing_input": "Please provide all required fields.",
        "gui.msg.error.password_mismatch": "Passwords do not match.",
        "gui.msg.error.no_file": "File does not exist.",
        "gui.msg.error.no_dir": "Directory does not exist.",
        "gui.button.github": "Open GitHub",
        "gui.button.info": "About",
        "gui.info.title": "About SecureArchive",
        "gui.info.text": (
            "SecureArchive\n"
            "Version 1.0\n\n"
            "A secure file and folder encryption engine.\n"
            "Features:\n"
            "- AES-256-GCM encryption\n"
            "- PBKDF2-SHA512 key derivation\n"
            "- Encrypted container format (.secarc)\n"
            "- Integrity verification\n"
            "- Password change with re-encryption\n\n"
            "Author: Thorsten\n"
        ),
    },

    "de": {
        "common.error": "Fehler",
        "common.done": "Abgeschlossen.",
        "common.language_set": "Sprache auf Deutsch gesetzt.",

        "password.prompt": "Passwort eingeben: ",
        "password.prompt_confirm": "Passwort bestätigen: ",
        "password.mismatch": "Passwörter stimmen nicht überein.",
        "password.current": "Aktuelles Passwort eingeben: ",
        "password.new": "Neues Passwort eingeben: ",
        "password.new_confirm": "Neues Passwort bestätigen: ",

        "encrypt.start": "Verschlüsselung wird gestartet...",
        "encrypt.success": "Verschlüsselung erfolgreich abgeschlossen.",
        "encrypt.overwrite_blocked": "Ausgabedatei existiert bereits. Verwenden Sie --force zum Überschreiben.",
        "encrypt.source_missing": "Eingabepfad existiert nicht.",
        "decrypt.start": "Entschlüsselung wird gestartet...",
        "decrypt.success": "Entschlüsselung erfolgreich abgeschlossen.",
        "list.start": "Container wird gelesen...",
        "list.header": "Container-Inhalt:",
        "list.entry": "{path} ({size} Bytes)",
        "verify.start": "Container-Integrität wird geprüft...",
        "verify.success": "Container-Integrität erfolgreich verifiziert.",
        "verify.failure": "Integritätsprüfung des Containers fehlgeschlagen.",
        "passwd.success": "Passwort erfolgreich geändert.",
        "error.invalid_container": "Ungültiges oder nicht unterstütztes Containerformat.",
        "error.wrong_password": "Entschlüsselung fehlgeschlagen – falsches Passwort oder beschädigte Daten.",
        "error.io": "Ein Ein-/Ausgabefehler ist aufgetreten.",
        "error.generic": "Ein unerwarteter Fehler ist aufgetreten.",

        "cli.description": "SecureArchive Engine – Dateien und Verzeichnisse sicher ver- und entschlüsseln.",
        "cli.lang_help": "Sprache für CLI-Ausgaben (en/de).",
        "cli.cmd.encrypt": "Dateien und Verzeichnisse verschlüsseln / Encrypt files and directories.",
        "cli.cmd.decrypt": "Container entschlüsseln / Decrypt a container.",
        "cli.cmd.list": "Container-Inhalt anzeigen / List container contents.",
        "cli.cmd.verify": "Container-Integrität prüfen / Verify container integrity.",
        "cli.cmd.passwd": "Container-Passwort ändern / Change container password.",
        "cli.arg.input": "Eingabedatei oder Verzeichnis / Input file or directory.",
        "cli.arg.output": "Ausgabedatei (Container) / Output container file.",
        "cli.arg.container": "Container-Datei / Container file.",
        "cli.arg.output_dir": "Ausgabe-Verzeichnis / Output directory.",
        "cli.arg.force": "Bestehende Ausgabedatei überschreiben / Overwrite existing output file.",
        "cli.arg.iterations": "PBKDF2-Iterationen für die Schlüsselableitung.",

        "gui.title": "SecureArchive – Datei- & Ordner-Verschlüsselung",
        "gui.lang.de": "Deutsch",
        "gui.lang.en": "English",
        "gui.status.ready": "Bereit.",
        "gui.status.running": "Vorgang läuft...",
        "gui.status.done": "Vorgang abgeschlossen.",
        "gui.status.error": "Vorgang fehlgeschlagen.",
        "gui.button.browse_file": "Datei wählen...",
        "gui.button.browse_folder": "Ordner wählen...",
        "gui.button.browse_container": "Container wählen...",
        "gui.button.browse_output_dir": "Zielordner wählen...",

        "gui.tab.encrypt": "Verschlüsseln",
        "gui.tab.decrypt": "Entschlüsseln",
        "gui.tab.list": "Auflisten",
        "gui.tab.verify": "Prüfen",
        "gui.tab.passwd": "Passwort ändern",

        "gui.encrypt.input_label": "Eingabe (Datei oder Ordner):",
        "gui.encrypt.output_label": "Ausgabe-Containerdatei:",
        "gui.encrypt.password_label": "Passwort:",
        "gui.encrypt.password_confirm_label": "Passwort bestätigen:",
        "gui.encrypt.iterations_label": "PBKDF2-Iterationen:",
        "gui.encrypt.force_label": "Bestehenden Container überschreiben",
        "gui.encrypt.button": "Verschlüsseln",

        "gui.decrypt.container_label": "Container-Datei:",
        "gui.decrypt.output_dir_label": "Zielverzeichnis:",
        "gui.decrypt.password_label": "Passwort:",
        "gui.decrypt.button": "Entschlüsseln",

        "gui.list.container_label": "Container-Datei:",
        "gui.list.password_label": "Passwort:",
        "gui.list.button": "Inhalt anzeigen",

        "gui.verify.container_label": "Container-Datei:",
        "gui.verify.password_label": "Passwort:",
        "gui.verify.button": "Prüfen",

        "gui.passwd.container_label": "Container-Datei:",
        "gui.passwd.current_label": "Aktuelles Passwort:",
        "gui.passwd.new_label": "Neues Passwort:",
        "gui.passwd.new_confirm_label": "Neues Passwort bestätigen:",
        "gui.passwd.iterations_label": "PBKDF2-Iterationen (optional):",
        "gui.passwd.button": "Passwort ändern",

        "gui.msg.encrypt.success": "Verschlüsselung erfolgreich abgeschlossen.",
        "gui.msg.decrypt.success": "Entschlüsselung erfolgreich abgeschlossen.",
        "gui.msg.list.success": "Container-Inhalt wurde angezeigt.",
        "gui.msg.verify.success": "Container-Integrität erfolgreich verifiziert.",
        "gui.msg.verify.failure": "Integritätsprüfung des Containers fehlgeschlagen.",
        "gui.msg.passwd.success": "Passwort erfolgreich geändert.",
        "gui.msg.error.missing_input": "Bitte alle erforderlichen Felder ausfüllen.",
        "gui.msg.error.password_mismatch": "Passwörter stimmen nicht überein.",
        "gui.msg.error.no_file": "Datei existiert nicht.",
        "gui.msg.error.no_dir": "Verzeichnis existiert nicht.",
        "gui.button.github": "GitHub öffnen",
        "gui.button.info": "Info",
        "gui.info.title": "Über SecureArchive",
        "gui.info.text": (
            "SecureArchive\n"
            "Version 1.0\n\n"
            "Eine sichere Datei- und Ordner-Verschlüsselungs-Engine.\n"
            "Funktionen:\n"
            "- AES-256-GCM Verschlüsselung\n"
            "- PBKDF2-SHA512 Schlüsselableitung\n"
            "- Verschlüsseltes Containerformat (.secarc)\n"
            "- Integritätsprüfung\n"
            "- Passwortwechsel mit Re-Verschlüsselung\n\n"
            "Autor: Thorsten\n"
        ),
    },
}

def tr(lang: str, key: str, **kwargs) -> str:
    lang_dict = I18N.get(lang) or I18N["en"]
    text = lang_dict.get(key, key)
    if kwargs:
        try:
            return text.format(**kwargs)
        except Exception:
            return text
    return text