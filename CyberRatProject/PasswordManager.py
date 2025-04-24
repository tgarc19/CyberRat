#sudo apt-get install python3-tk
#pip install cryptography OR pip install crytpography==2.5 ? maybe not needed, helped to resolve import problems depends on what python version you are using.
#python3 passwordmaangertk (to run)
import hashlib
import os
import json
import base64
import tkinter as tk
from tkinter import messagebox, ttk
from cryptography.fernet import Fernet

# Files
CREDENTIALS_FILE = "passwords.json"
MASTER_PASSWORD_FILE = "master_password.json"
master_password = None

def master_password_exists():
    return os.path.exists(MASTER_PASSWORD_FILE)

def set_global_master(pm_str):
    global master_password
    master_password = pm_str

def get_global_master():
    return master_password

def get_hashed_master_password():
    if os.path.exists(MASTER_PASSWORD_FILE):
        with open(MASTER_PASSWORD_FILE, "r") as file:
            return json.load(file)["hashed_master_password"]
    return None

def save_master_password(password: str):
    hashed_pw = hash_password(password)
    with open(MASTER_PASSWORD_FILE, "w") as file:
        json.dump({"hashed_master_password": hashed_pw.hex()}, file)

def verify_master_password(input_password):
    if not os.path.exists(MASTER_PASSWORD_FILE):
        return False
    with open(MASTER_PASSWORD_FILE, "r") as f:
        stored_hash = json.load(f)["hashed_master_password"]
    return hash_password(input_password).hex() == stored_hash

def hash_password(password: str) -> bytes:
    return hashlib.sha256(password.encode()).digest()

def encrypt_password(password: str, key: str) -> str:
    hashed_key = hashlib.sha256(key.encode()).digest()
    cipher = Fernet(base64.urlsafe_b64encode(hashed_key))
    return cipher.encrypt(password.encode()).decode()

def decrypt_password(encrypted_password: str, key: str) -> str:
    if get_global_master is None:
        return "No MasterPassword"
    hashed_key = hashlib.sha256(key.encode()).digest()
    cipher = Fernet(base64.urlsafe_b64encode(hashed_key))
    try:
        return cipher.decrypt(encrypted_password.encode()).decode()
    except Exception:
        return "[Decryption failed]"

def save_credentials(service: str, username: str, password: str):
    encrypted_password = encrypt_password(password, master_password)

    credentials = load_credentials()
    credentials[service] = {
        "username": username,
        "password": encrypted_password
    }

    with open(CREDENTIALS_FILE, "w") as file:
        json.dump(credentials, file, indent=4)

def load_credentials():
    if os.path.exists(CREDENTIALS_FILE):
        with open(CREDENTIALS_FILE, "r") as f:
            return json.load(f)
    return []

def save_all_credentials(credentials: list):
    with open(CREDENTIALS_FILE, "w") as f:
        json.dump(credentials, f, indent=4)

def append_credential(service, username, password):
    credentials = load_credentials()
    credentials.append({
        "service": service,
        "username": username,
        "password": encrypt_password(password, get_global_master())
    })
    save_all_credentials(credentials)
