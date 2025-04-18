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

def set_global_master(pm_str):
    global master_password
    master_password = pm_str

def get_global_master():
    return master_password

def master_password_exists():
    return os.path.exists(MASTER_PASSWORD_FILE)

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

def set_master_password(entry):
    global master_password
    master_password = entry

def verify_master_password() -> bool:
    if not os.path.exists(MASTER_PASSWORD_FILE):
        return False

    with open(MASTER_PASSWORD_FILE, "r") as file:
        master_data = json.load(file)

    stored_hash = bytes.fromhex(master_data["hashed_master_password"])

    global master_password
    computed_hash = hash_password(master_password)

    return computed_hash == stored_hash

def save_credentials(service: str, username: str, password: str):
    encrypted_password = encrypt_password(password, master_password)

    credentials = load_credentials()
    credentials[service] = {
        "username": username,
        "password": encrypted_password
    }

    with open(CREDENTIALS_FILE, "w") as file:
        json.dump(credentials, file, indent=4)

def save_all_credentials(credentials: dict):
    with open(CREDENTIALS_FILE, "w") as file:
        json.dump(credentials, file, indent=4)

def load_credentials() -> dict:
    if os.path.exists(CREDENTIALS_FILE):
        with open(CREDENTIALS_FILE, "r") as file:
            return json.load(file)
    return {}

def get_services() -> list:
    credentials = load_credentials()
    return list(credentials.keys())

#def display_all_credentials():
    #credentials = load_credentials()
    #if not credentials:
        #messagebox.showinfo("No Data", "No credentials stored.")
        #return

    #window = tk.Toplevel()
    #window.title("Stored Credentials")

    #tree = ttk.Treeview(window, columns=("Service", "Username", "Password"), show="headings")
    #tree.heading("Service", text="Service")
    #tree.heading("Username", text="Username")
    #tree.heading("Password", text="Password")

    #for service, data in credentials.items():
        #decrypted_password = decrypt_password(data['password'], master_password)
        #tree.insert("", "end", values=(service, data['username'], decrypted_password))

    #tree.pack(expand=True, fill="both")

#def show_services():
    #services = get_services()
    #if not services:
        #messagebox.showinfo("No Services", "No services stored.")
        #return
    #messagebox.showinfo("Stored Services", "\n".join(services))

#def toggle_add_credential_form(add_btn, container):
    #if hasattr(container, 'form_visible') and container.form_visible:
        #container.form_frame.destroy()
        #container.form_visible = False
    #else:
        #container.form_frame = tk.Frame(container)
        #container.form_frame.pack(pady=10)

        #tk.Label(container.form_frame, text="Service").grid(row=0, column=0, padx=5, pady=2)
       #tk.Label(container.form_frame, text="Username").grid(row=1, column=0, padx=5, pady=2)
        #tk.Label(container.form_frame, text="Password").grid(row=2, column=0, padx=5, pady=2)

        #service_entry = tk.Entry(container.form_frame)
        #username_entry = tk.Entry(container.form_frame)
        #password_entry = tk.Entry(container.form_frame, show='*')

        #service_entry.grid(row=0, column=1, padx=5, pady=2)
        #username_entry.grid(row=1, column=1, padx=5, pady=2)
        #password_entry.grid(row=2, column=1, padx=5, pady=2)

        #def save_and_hide():
            #service = service_entry.get()
            #username = username_entry.get()
            #password = password_entry.get()
            #save_credentials(service, username, password)
            #messagebox.showinfo("Saved", "Credential saved!")
            #toggle_add_credential_form(add_btn, container)  # hide the form

        #tk.Button(container.form_frame, text="Save Credential", command=save_and_hide).grid(row=3, columnspan=2, pady=5)

        #container.form_visible = True

#def main_gui():
    #global master_password

    #root = tk.Tk()
    #root.title("Password Manager")
    #root.geometry("400x400")

    # Frames
    #login_frame = tk.Frame(root)
    #main_frame = tk.Frame(root)

    # Login Frame UI
    #tk.Label(login_frame, text="Enter Master Password", font=("Arial", 14)).pack(pady=10)
    #password_entry = tk.Entry(login_frame, show='*', width=30)
    #password_entry.pack(pady=5)
    #tk.Button(login_frame, text="Submit", command=lambda: set_master_password_from_gui(password_entry, root, login_frame, main_frame)).pack(pady=10)
    #login_frame.pack(fill='both', expand=True)

    # Main Frame UI
    #tk.Label(main_frame, text="Password Manager", font=("Arial", 16)).pack(pady=10)
    #tk.Button(main_frame, text="View Services", width=30, command=show_services).pack(pady=5)
    #tk.Button(main_frame, text="View Credentials", width=30, command=display_all_credentials).pack(pady=5)

    #add_btn = tk.Button(main_frame, text="Add New Credential", width=30)
    #add_btn.pack(pady=5)
    #add_btn.config(command=lambda: toggle_add_credential_form(add_btn, main_frame))

    #tk.Button(main_frame, text="Exit", width=30, command=root.destroy).pack(pady=5)

    #root.mainloop()