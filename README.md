# LockerBox
**Secure. Control. Protect.**

Locker Box is a secure, menu-driven file encryption and decryption tool for Windows that lets you protect, hide, and manage your files with ease. Built for convenience, it allows you to encrypt files with a password, decrypt them when needed, and store them in a hidden vault accessible only with your master password. 

---
## Features
- 🔒 Encrypt & hide any file type (.jpg, .mp4, .mp3, .pdf, etc.)
- 🔑 Master-password protected vault (Argon2 + Fernet)
- 🔢 Numbered unlock & listing for easy selection
- 🧰 Interactive, beginner-friendly CLI
- 🖥 Standalone `.exe` available via Releases — no Python required

---

## 📂 File Structure
Lockerbox/
│── Lockerbox.py # Main Python script
│── lockerbox.exe # Compiled executable (for Windows users)
│── requirements.txt # Dependencies
│── README.md # Documentation

---

## ⚙️ Installation
### Option A — Run the EXE (recommended)
1. Download `lockerbox.exe` from the Releases page of this repository.
2. Run it by double-clicking or from PowerShell:
   ```powershell
   .\lockerbox.exe

### Option B — Run from source
1.Install Python 3.10+.
2.Clone the repo:
        git clone https://github.com/Dev-Ananth/LockerBox.git
        cd LockerBox
3.(Optional) Create and activate a virtual env:
        python -m venv venv
        .\venv\Scripts\Activate.ps1
4.Install dependencies:
        pip install -r requirements.txt
5.Run:
        python Lockerbox.py


