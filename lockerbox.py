#!/usr/bin/env python3
"""
LOCKER BOX — Secure. Control. Protect.
Final user-friendly Windows CLI vault (master password + hidden vault)
"""
import os
import sys
import json
import time
import secrets
import base64
from pathlib import Path
import getpass

# crypto
from cryptography.fernet import Fernet
from argon2 import PasswordHasher
from argon2.low_level import hash_secret_raw, Type

# UI
from colorama import Fore, Style, init
init(autoreset=True)
try:
    import pyfiglet
    _HAS_PFIG = True
except Exception:
    _HAS_PFIG = False

# optional GUI file picker
try:
    import tkinter as tk
    from tkinter import filedialog
    _HAS_TK = True
except Exception:
    _HAS_TK = False

# --------------- Config & Paths ---------------
HOME = Path.home()
VAULT_DIR = HOME / ".locker_vault"                 # hidden folder in user home
META_FILE = VAULT_DIR / "locker_meta.json"
MASTER_HASH_FILE = VAULT_DIR / "master.hash"
KDF_SALT_FILE = VAULT_DIR / "kdf_salt.bin"

COMMON_FOLDERS = [
    Path.cwd(),
    HOME / "Downloads",
    HOME / "Desktop",
    HOME / "Documents",
    HOME / "Pictures",
    HOME / "Videos",
    HOME / "Music",
]

ph = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=2)

# --------------- Helpers ---------------
def ensure_vault():
    VAULT_DIR.mkdir(parents=True, exist_ok=True)
    # hide folder (hidden attribute only, avoids requiring admin)
    try:
        os.system(f'attrib +h "{VAULT_DIR}"')
    except Exception:
        pass
    if not META_FILE.exists():
        META_FILE.write_text(json.dumps({"files": {}}, indent=2))

def load_meta():
    ensure_vault()
    try:
        return json.loads(META_FILE.read_text())
    except Exception:
        return {"files": {}}

def save_meta(m):
    ensure_vault()
    META_FILE.write_text(json.dumps(m, indent=2))

def gen_salt():
    s = secrets.token_bytes(16)
    KDF_SALT_FILE.write_bytes(s)
    return s

def load_salt():
    if not KDF_SALT_FILE.exists():
        return gen_salt()
    return KDF_SALT_FILE.read_bytes()

def derive_fernet_key(password: str, salt: bytes) -> bytes:
    raw = hash_secret_raw(password.encode('utf-8'), salt,
                          time_cost=3, memory_cost=65536,
                          parallelism=2, hash_len=32, type=Type.ID)
    return base64.urlsafe_b64encode(raw)

def banner():
    if _HAS_PFIG:
        print(Fore.MAGENTA + pyfiglet.figlet_format("LOCKER BOX", font="standard"))
    else:
        print(Fore.MAGENTA + Style.BRIGHT + "=== LOCKER BOX ===")
    print(Fore.GREEN + "Secure. Control. Protect.\n")

def strip_input(s):
    return (s or "").strip().strip('"').strip("'")

def pause():
    input(Fore.CYAN + "\nPress Enter to return to menu...")

# --------------- Master Password Setup / Verify ---------------
def setup_master():
    ensure_vault()
    if MASTER_HASH_FILE.exists():
        print(Fore.YELLOW + "Master password already set.")
        return
    print(Fore.YELLOW + "First-time setup — create your master password.")
    while True:
        pw = getpass.getpass("Set master password: ")
        pw2 = getpass.getpass("Confirm password: ")
        if not pw:
            print(Fore.RED + "Password cannot be empty.")
            continue
        if pw != pw2:
            print(Fore.RED + "Passwords do not match — try again.")
            continue
        MASTER_HASH_FILE.write_text(ph.hash(pw))
        load_salt()  # generate and store salt
        print(Fore.GREEN + "Master password saved! Remember it — no recovery.")
        break

def verify_master():
    if not MASTER_HASH_FILE.exists():
        print(Fore.RED + "Vault not initialized. Run Setup from menu first.")
        return None
    stored = MASTER_HASH_FILE.read_text()
    for _ in range(3):
        pw = getpass.getpass("Enter master password: ")
        try:
            ph.verify(stored, pw)
            salt = load_salt()
            key = derive_fernet_key(pw, salt)
            return Fernet(key)
        except Exception:
            print(Fore.RED + "Wrong password. Try again.")
    print(Fore.RED + "Too many failures.")
    return None

# --------------- File search + picker ---------------
def find_candidates(query, maxn=50):
    q = strip_input(query).lower()
    if not q:
        return []
    if os.path.isabs(q):
        p = Path(q)
        return [str(p.resolve())] if p.exists() else []
    results = []
    for folder in COMMON_FOLDERS:
        try:
            p = folder / q
            if p.exists():
                return [str(p.resolve())]
        except Exception:
            pass
    for folder in COMMON_FOLDERS:
        if not folder.exists():
            continue
        try:
            for root, _, files in os.walk(folder):
                for fn in files:
                    if q in fn.lower():
                        path = os.path.join(root, fn)
                        if path not in results:
                            results.append(path)
                            if len(results) >= maxn:
                                return results
        except PermissionError:
            continue
    return results

def open_file_picker():
    if not _HAS_TK:
        return None
    root = tk.Tk()
    root.withdraw()
    path = filedialog.askopenfilename(title="Select file to lock")
    root.destroy()
    return path or None

# --------------- Encrypt / Decrypt ---------------
def encrypt_and_hide(fernet: Fernet, filepath: str):
    p = Path(filepath)
    if not p.exists():
        print(Fore.RED + "File missing. Aborting.")
        return False
    data = p.read_bytes()
    token = fernet.encrypt(data)
    uid = secrets.token_hex(12)
    vault_name = f"{uid}.lbx"
    vault_path = VAULT_DIR / vault_name
    vault_path.write_bytes(token)
    meta = load_meta()
    meta["files"][p.name] = {
        "vault": str(vault_path),
        "original_path": str(p.resolve()),
        "size": p.stat().st_size,
        "ts": int(time.time())
    }
    save_meta(meta)
    try:
        p.unlink()
    except Exception:
        pass
    print(Fore.GREEN + f"✅ '{p.name}' encrypted and hidden in vault as '{vault_name}'")
    return True

def decrypt_and_restore(fernet: Fernet, original_name: str, out_path: str = None):
    meta = load_meta()
    ent = meta.get("files", {}).get(original_name)
    if not ent:
        print(Fore.RED + "File not found in vault metadata.")
        return False
    vault_path = Path(ent["vault"])
    if not vault_path.exists():
        print(Fore.RED + "Encrypted blob missing from vault.")
        return False
    token = vault_path.read_bytes()
    try:
        data = fernet.decrypt(token)
    except Exception:
        print(Fore.RED + "❌ Decryption failed — wrong password or corrupted data.")
        return False
    if out_path:
        out = Path(out_path)
    else:
        try:
            out = Path(ent["original_path"])
        except Exception:
            out = Path.cwd() / original_name
    try:
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_bytes(data)
    except Exception:
        out = Path.cwd() / original_name
        out.write_bytes(data)
    try:
        vault_path.unlink()
    except Exception:
        pass
    meta["files"].pop(original_name, None)
    save_meta(meta)
    print(Fore.GREEN + f"🔓 '{original_name}' decrypted and restored to: {out.resolve()}")
    return True

# --------------- Menus ---------------
def menu_encrypt():
    q = input(Fore.YELLOW + "Enter filename (or partial name) e.g. cat.jpg: ").strip()
    q = strip_input(q)
    if not q:
        print(Fore.RED + "Empty input. Aborting.")
        return
    candidates = find_candidates(q)
    chosen = None
    if len(candidates) == 0:
        print(Fore.YELLOW + "No match in common folders.")
        pick = input("Open file picker? (Y/n): ").strip().lower()
        if pick == "n":
            print(Fore.RED + "Cancelled.")
            return
        path = open_file_picker()
        if not path:
            print(Fore.RED + "No file selected. Cancelled.")
            return
        chosen = path
    elif len(candidates) == 1:
        chosen = candidates[0]
    else:
        print(Fore.CYAN + "Multiple matches found:")
        for i, p in enumerate(candidates, start=1):
            print(Fore.YELLOW + f"[{i}] " + Fore.WHITE + p)
        print(Fore.YELLOW + "[0] Cancel")
        sel = input("Choose number: ").strip()
        if not sel.isdigit():
            print(Fore.RED + "Invalid choice.")
            return
        idx = int(sel)
        if idx == 0:
            print(Fore.RED + "Cancelled.")
            return
        if 1 <= idx <= len(candidates):
            chosen = candidates[idx - 1]
        else:
            print(Fore.RED + "Out of range.")
            return
    fernet = verify_master()
    if not fernet:
        return
    print(Fore.CYAN + f"Encrypt and hide: {chosen}")
    if input("Proceed? (Y/n): ").strip().lower() == "n":
        print(Fore.YELLOW + "Cancelled.")
        return
    encrypt_and_hide(fernet, chosen)

def menu_list():
    fernet = verify_master()
    if not fernet:
        return
    meta = load_meta()
    files = list(meta.get("files", {}).items())
    if not files:
        print(Fore.YELLOW + "Vault is empty.")
        return
    print(Fore.CYAN + "Files in vault:")
    for i, (name, info) in enumerate(files, start=1):
        ts = time.ctime(info.get("ts", 0))
        size = info.get("size", "?")
        print(Fore.YELLOW + f"[{i}] " + Fore.WHITE + f"{name}  — {size} bytes  — {ts}")

def menu_decrypt():
    fernet = verify_master()
    if not fernet:
        return
    meta = load_meta()
    files = list(meta.get("files", {}).items())
    if not files:
        print(Fore.YELLOW + "Vault is empty.")
        return
    print(Fore.CYAN + "Choose file to decrypt:")
    for i, (name, _) in enumerate(files, start=1):
        print(Fore.YELLOW + f"[{i}] " + Fore.WHITE + name)
    print(Fore.YELLOW + "[0] Cancel")
    sel = input("Select number or enter filename: ").strip()
    if sel.isdigit():
        idx = int(sel)
        if idx == 0:
            print(Fore.YELLOW + "Cancelled.")
            return
        if 1 <= idx <= len(files):
            original_name = files[idx - 1][0]
        else:
            print(Fore.RED + "Invalid number.")
            return
    else:
        original_name = strip_input(sel)
        if original_name not in meta.get("files", {}):
            print(Fore.RED + "Filename not found in vault metadata.")
            return
    out = input(Fore.CYAN + f"Output filename (press Enter to restore original '{original_name}'): ").strip()
    out = out or None
    decrypt_and_restore(fernet, original_name, out)

# --------------- Main ---------------
def main():
    ensure_vault()
    while True:
        banner()
        print(Fore.MAGENTA + "[1] Lock/encrypt a file")
        print(Fore.MAGENTA + "[2] Unlock/decrypt a file")
        print(Fore.MAGENTA + "[3] List vault (requires master pass)")
        print(Fore.MAGENTA + "[4] Setup / Reset master password (danger: resetting loses access)")
        print(Fore.MAGENTA + "[5] Exit\n")
        choice = input(Fore.YELLOW + "Select an option: ").strip()
        if choice == "1":
            try:
                menu_encrypt()
            except Exception as e:
                print(Fore.RED + f"Error: {e}")
            pause()
        elif choice == "2":
            try:
                menu_decrypt()
            except Exception as e:
                print(Fore.RED + f"Error: {e}")
            pause()
        elif choice == "3":
            try:
                menu_list()
            except Exception as e:
                print(Fore.RED + f"Error: {e}")
            pause()
        elif choice == "4":
            print(Fore.YELLOW + "WARNING: resetting master password will make existing vault unreadable unless you know current password.")
            yn = input("Continue with setup/reset? (Y/n): ").strip().lower()
            if yn == "y":
                print(Fore.RED + "You must type 'RESET' to proceed.")
                if input("Type now: ").strip() == "RESET":
                    try:
                        MASTER_HASH_FILE.unlink(missing_ok=True)
                        KDF_SALT_FILE.unlink(missing_ok=True)
                    except Exception:
                        pass
                    print(Fore.GREEN + "Master password removed. On next run you'll create a new password (existing vault will be inaccessible without old password).")
        elif choice == "5":
            print(Fore.GREEN + "Goodbye!")
            sys.exit(0)
        else:
            print(Fore.RED + "Invalid option. Try again.")
            pause()

if __name__ == "__main__":
    main()
