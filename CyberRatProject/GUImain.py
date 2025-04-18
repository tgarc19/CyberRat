
# Authors:
# Tiago Garcia, William Parker, Luke Robinson

# install Npcap here -> https://npcap.com/#download
# install python then these packages
# pip install scapy, cryptography, customtkinter, pyperclip

from scapy.all import ARP, Ether, srp
from FileEncryption import FileEncryptor as fe
from tkinter import filedialog, messagebox
import customtkinter as ctk
import PasswordManager as pm
import os
import random
import string
import threading
import ctypes
import sys
import pyperclip

def elevate_as_admin():
    if not ctypes.windll.shell32.IsUserAnAdmin():
        # Relaunch with admin privileges
        ctypes.windll.shell32.ShellExecuteW(
            None,
            "runas",
            sys.executable,
            " ".join([f'"{arg}"' for arg in sys.argv]),
            None,
            1
        )
        sys.exit()

def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False
    
class App(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("Cyber Rat")
        self.geometry("900x600")

        # Container for all scenes
        self.container = ctk.CTkFrame(self)
        self.container.pack(fill="both", expand=True)

        # Dictionary to hold different frames (scenes)
        self.frames = {}

        for F in (HomeScene, NmapScene, PasswordScene, FileEncryptScene):
            frame = F(parent=self.container, controller=self)
            self.frames[F.__name__] = frame
            frame.grid(row=0, column=0, sticky="nsew")

        self.show_frame("HomeScene")

    def show_frame(self, scene_name):
        frame = self.frames[scene_name]
        frame.tkraise()

class HomeScene(ctk.CTkFrame):
    def __init__(self, parent, controller):
        super().__init__(parent)
        self.controller = controller

        # Title Label
        title_label = ctk.CTkLabel(
            self, text="CyberRat", 
            font=ctk.CTkFont(size=64, weight="bold"),
            corner_radius=10,
            padx=20, pady=10
        )
        title_label.pack(pady=40)

        # Subtitle Label (Tool List)
        subtitle_label = ctk.CTkLabel(
            self, text="Tool List", 
            font=ctk.CTkFont(size=24),
            corner_radius=6,
            padx=10, pady=5
        )
        subtitle_label.pack(pady=10)

        # Button Row Frame
        button_frame = ctk.CTkFrame(self, fg_color="transparent")
        button_frame.pack(pady=20)

        # Buttons in a row
        encrypt_button = ctk.CTkButton(
            button_frame, text="Encrypt", width=100,
            command=lambda: controller.show_frame("FileEncryptScene")
        )
        encrypt_button.grid(row=0, column=0, padx=10)

        nmap_button = ctk.CTkButton(
            button_frame, text="Nmap", width=100,
            command=lambda: controller.show_frame("NmapScene")
        )
        nmap_button.grid(row=0, column=1, padx=10)

        password_button = ctk.CTkButton(
            button_frame, text="PassManage", width=100,
            command=lambda: controller.show_frame("PasswordScene")
        )
        password_button.grid(row=0, column=2, padx=10)

class NmapScene(ctk.CTkFrame):
    def __init__(self, parent, controller):
        super().__init__(parent)
        self.controller = controller

        # === Top Navigation Bar ===
        nav_bar = ctk.CTkFrame(self, fg_color="transparent")
        nav_bar.pack(fill="x", padx=20, pady=10)

        nav_buttons = ctk.CTkFrame(nav_bar, fg_color="transparent")
        nav_buttons.pack(side="left")

        for text, scene in [
            ("CyberRat", "HomeScene"),
            ("Encrypt", "FileEncryptScene"),
            ("Nmap", "NmapScene"),
            ("PassManage", "PasswordScene")
        ]:
            btn = ctk.CTkButton(nav_buttons, text=text, width=100,
                                command=lambda s=scene: controller.show_frame(s))
            btn.pack(side="left", padx=5)

        right_side = ctk.CTkFrame(nav_bar, fg_color="transparent")
        right_side.pack(side="right")

        config_button = ctk.CTkButton(right_side, text="Config", width=30)
        config_button.pack(side="left", padx=5)

        help_button = ctk.CTkButton(right_side, text="?", width=30)
        help_button.pack(side="left")

        # === IP Input Area ===
        ip_input_frame = ctk.CTkFrame(self, fg_color="transparent")
        ip_input_frame.pack(pady=(10, 5), padx=40, anchor="w")

        ip_label = ctk.CTkLabel(ip_input_frame, text="IP address")
        ip_label.pack(anchor="w")

        entry_frame = ctk.CTkFrame(ip_input_frame, fg_color="transparent")
        entry_frame.pack(fill="x", pady=5)

        self.ip_entry = ctk.CTkEntry(entry_frame, width=400)
        self.ip_entry.pack(side="left")

        map_btn = ctk.CTkButton(entry_frame, text="Map", width=80, command=self.run_arp_scan)
        map_btn.pack(side="left", padx=10)

        filter_btn = ctk.CTkButton(entry_frame, text="Filter", width=80)
        filter_btn.pack(side="left")

        # === Output Frame ===
        self.output_box = ctk.CTkTextbox(self, width=800, height=400, wrap="none")
        self.output_box.pack(pady=20, padx=40)

    def run_arp_scan(self):
        ip_range = self.ip_entry.get().strip()
        if not ip_range:
            self.output_box.insert("end", "Please enter an IP range (e.g., 192.168.1.1/24)\n")
            return

        # Run scan in thread to prevent freezing GUI
        threading.Thread(target=self.perform_arp_scan, args=(ip_range,), daemon=True).start()
    
    def perform_arp_scan(self, ip_range):
        self.output_box.delete("1.0", "end")
        self.output_box.insert("end", f"Scanning {ip_range}...\n")

        try:
            ether = Ether(dst="ff:ff:ff:ff:ff:ff")
            arp = ARP(pdst=ip_range)
            packet = ether / arp

            result = srp(packet, timeout=2, verbose=0)[0]

            if not result:
                self.output_box.insert("end", "No hosts found.\n")
                return

            for sent, received in result:
                self.output_box.insert("end", f"{received.psrc} - {received.hwsrc}\n")
        except Exception as e:
            self.output_box.insert("end", f"Error: {e}\n")

class PasswordScene(ctk.CTkFrame):


    def __init__(self, parent, controller):
        super().__init__(parent)
        self.controller = controller
    
        self.show_master_password_popup()
        
        # === Top Navigation Bar ===
        nav_bar = ctk.CTkFrame(self, fg_color="transparent")
        nav_bar.pack(fill="x", padx=20, pady=10)

        nav_buttons = ctk.CTkFrame(nav_bar, fg_color="transparent")
        nav_buttons.pack(side="left")

        for text, scene in [
            ("CyberRat", "HomeScene"),
            ("Encrypt", "FileEncryptScene"),
            ("Nmap", "NmapScene"),
            ("PassManage", "PasswordScene")
        ]:
            btn = ctk.CTkButton(nav_buttons, text=text, width=100,
                                command=lambda s=scene: controller.show_frame(s))
            btn.pack(side="left", padx=5)

        right_side = ctk.CTkFrame(nav_bar, fg_color="transparent")
        right_side.pack(side="right")

        config_button = ctk.CTkButton(right_side, text="Config", width=30)
        config_button.pack(side="left", padx=5)

        help_button = ctk.CTkButton(right_side, text="?", width=30)
        help_button.pack(side="left")

        # === Search Bar ===
        search_frame = ctk.CTkFrame(self, fg_color="transparent")
        search_frame.pack(pady=10)

        self.search_entry = ctk.CTkEntry(search_frame, placeholder_text="Search...", width=300)
        self.search_entry.pack(side="left", padx=5)

        search_icon = ctk.CTkButton(search_frame, text="🔍", width=40)
        search_icon.pack(side="left")

        # === Scrollable Area ===
        self.entries_frame = ctk.CTkScrollableFrame(self, width=880, height=350)
        self.entries_frame.pack(pady=10)

        self.display_credentials()

        # === ADD Button ===
        add_button = ctk.CTkButton(self, text="ADD", width=200, command=self.open_add_popup)
        add_button.pack(pady=20)

    def open_add_popup(self):
        popup = ctk.CTkToplevel(self)
        popup.title("Add Password")
        popup.geometry("400x300")
        popup.grab_set()

        input_frame = ctk.CTkFrame(popup)
        input_frame.pack(padx=20, pady=20)

        # === Service Entry ===
        ctk.CTkLabel(input_frame, text="Service").pack(anchor="w")
        service_entry = ctk.CTkEntry(input_frame, width=300)
        service_entry.pack(pady=5)

        # === Username Entry ===
        ctk.CTkLabel(input_frame, text="Username").pack(anchor="w")
        username_entry = ctk.CTkEntry(input_frame, width=300)
        username_entry.pack(pady=5)

        # === Password Entry + Auto Generate ===
        password_label = ctk.CTkLabel(input_frame, text="Enter Password")
        password_label.pack(anchor="w", pady=(10, 5))
        pw_frame = ctk.CTkFrame(input_frame, fg_color="transparent")
        pw_frame.pack(pady=5)

        password_entry = ctk.CTkEntry(pw_frame, width=200)
        password_entry.insert(0, self.generate_password())
        password_entry.pack(side="left")

        generate_btn = ctk.CTkButton(pw_frame, text="Auto Generate", width=120,
                                 command=lambda: password_entry.delete(0, "end") or password_entry.insert(0, self.generate_password()))
        generate_btn.pack(side="left", padx=5)

        def save():
            service = service_entry.get()
            username = username_entry.get()
            password = password_entry.get()
            if service and username and password:
                pm.save_credentials(service, username, password)
                self.display_credentials()
                popup.destroy()
            else:
                messagebox.showwarning("Missing Info", "Please fill all fields.")

        ctk.CTkButton(input_frame, text="ADD", width=200, command=save).pack(pady=15)

    def show_master_password_popup(self):
        popup = ctk.CTkToplevel(self)
        popup.title("Enter Master Password")
        popup.geometry("400x200")
        popup.grab_set()
        popup.resizable(False, False)

        ctk.CTkLabel(popup, text="Enter Master Password", font=ctk.CTkFont(size=16)).pack(pady=20)

        password_entry = ctk.CTkEntry(popup, show="*", width=250)
        password_entry.pack(pady=10)

        def submit_password():
            password = password_entry.get()

            if not os.path.exists(pm.MASTER_PASSWORD_FILE):
                # First-time setup: Save hashed password
                pm.set_global_master(password)
                messagebox.showinfo("Success", "Master password created!")
                popup.destroy()
            elif pm.verify_master_password(password):
                pm.set_global_master(password)
                popup.destroy()
            else:
                messagebox.showerror("Access Denied", "Incorrect master password")

        ctk.CTkButton(popup, text="Submit", command=submit_password).pack(pady=10)

    def generate_password(self, length=12):
        characters = string.ascii_letters + string.digits + "!@#$%^&*()"
        return ''.join(random.choices(characters, k=length))

    def save_password(self, service, username, password, popup_window):
        print(f"Saved: {service} | {username} | {password}")
        popup_window.destroy()
        
    def display_credentials(self):
        for widget in self.entries_frame.winfo_children():
            widget.destroy()

        credentials = pm.load_credentials()
        if not credentials:
            empty_label = ctk.CTkLabel(self.entries_frame, text="No stored credentials.")
            empty_label.pack()
            return

        for service, data in credentials.items():
            frame = HoverFrame(self.entries_frame)
            frame.pack(fill="x", pady=2, padx=5)

            site_label = ctk.CTkLabel(frame, text=service, width=200, anchor="w")
            site_label.grid(row=0, column=0, padx=5)

            user_label = ctk.CTkLabel(frame, text=data['username'], width=150, anchor="w")
            user_label.grid(row=0, column=1, padx=5)

            decrypted = pm.decrypt_password(data['password'], pm.get_global_master())
            password_label = ctk.CTkLabel(frame, text=decrypted, width=200, anchor="w")
            password_label.grid(row=0, column=2, padx=5)

            def copy_to_clipboard(pwd=decrypted):
                pyperclip.copy(pwd)
                messagebox.showinfo("Copied", "Password copied to clipboard")

            def edit_entry(s=service):
                self.open_edit_popup(s, data['username'], decrypted)

            def delete_entry(s=service):
                confirm = messagebox.askyesno("Confirm Delete", f"Delete credentials for {s}?")
                if confirm:
                    creds = pm.load_credentials()
                    if s in creds:
                        del creds[s]
                        pm.save_all_credentials(creds)
                        self.display_credentials()

            copy_button = ctk.CTkButton(frame, text="Copy", width=70, command=copy_to_clipboard)
            edit_button = ctk.CTkButton(frame, text="Edit", width=70, command=edit_entry)
            delete_button = ctk.CTkButton(frame, text="🗑️", width=30, fg_color="red", text_color="white", command=delete_entry)

            copy_button.grid(row=0, column=3, padx=5)
            edit_button.grid(row=0, column=4, padx=5)
            delete_button.grid(row=0, column=5, padx=5)

            frame.set_hover_widgets([copy_button, edit_button, delete_button])

    def open_edit_popup(self, service, username, password):
        popup = ctk.CTkToplevel(self)
        popup.title("Edit Credential")
        popup.geometry("400x300")
        popup.grab_set()

        frame = ctk.CTkFrame(popup)
        frame.pack(padx=20, pady=20)

        ctk.CTkLabel(frame, text="Service").pack(anchor="w")
        service_entry = ctk.CTkEntry(frame, width=300)
        service_entry.insert(0, service)
        service_entry.pack(pady=5)

        ctk.CTkLabel(frame, text="Username").pack(anchor="w")
        username_entry = ctk.CTkEntry(frame, width=300)
        username_entry.insert(0, username)
        username_entry.pack(pady=5)

        ctk.CTkLabel(frame, text="Password").pack(anchor="w")
        password_entry = ctk.CTkEntry(frame, width=300)
        password_entry.insert(0, password)
        password_entry.pack(pady=5)

        def save_changes():
            new_service = service_entry.get()
            new_username = username_entry.get()
            new_password = password_entry.get()
            if new_service and new_username and new_password:
                creds = pm.load_credentials()
                if service in creds:
                    del creds[service]
                creds[new_service] = {
                    "username": new_username,
                    "password": pm.encrypt_password(new_password, pm.get_global_master())
                }
                pm.save_all_credentials(creds)
                self.display_credentials()
                popup.destroy()
            else:
                messagebox.showwarning("Missing Info", "Please fill all fields.")

        ctk.CTkButton(frame, text="SAVE", command=save_changes).pack(pady=15)

class HoverFrame(ctk.CTkFrame):
    def __init__(self, parent):
        super().__init__(parent)
        self.hover_widgets = []
        self.hovering = False

        # Track enter/leave for the frame itself
        self.bind("<Enter>", self.on_enter)
        self.bind("<Leave>", self.on_leave)

    def set_hover_widgets(self, widgets):
        self.hover_widgets = widgets
        for widget in widgets:
            widget.grid_remove()

            # Track enter/leave on each button too
            widget.bind("<Enter>", self.on_enter)
            widget.bind("<Leave>", self.on_leave)

    def on_enter(self, event=None):
        self.hovering = True
        for widget in self.hover_widgets:
            widget.grid()

    def on_leave(self, event=None):
        self.hovering = False
        self.after(150, self.check_if_still_hovering)

    def check_if_still_hovering(self):
        widget = self.winfo_containing(self.winfo_pointerx(), self.winfo_pointery())
        if widget in [self] + self.hover_widgets:
            self.hovering = True

        if not self.hovering:
            for widget in self.hover_widgets:
                widget.grid_remove()

class FileEncryptScene(ctk.CTkFrame):
    def __init__(self, parent, controller):
        super().__init__(parent)
        self.controller = controller

        # === Top Navigation Bar ===
        nav_bar = ctk.CTkFrame(self, fg_color="transparent")
        nav_bar.pack(fill="x", padx=20, pady=10)

        # Left-aligned nav buttons
        nav_buttons = ctk.CTkFrame(nav_bar, fg_color="transparent")
        nav_buttons.pack(side="left")

        for text, scene in [
            ("CyberRat", "HomeScene"),
            ("Encrypt", "FileEncryptScene"),
            ("Nmap", "NmapScene"),
            ("PassManage", "PasswordScene")
        ]:
            btn = ctk.CTkButton(nav_buttons, text=text, width=100,
                                command=lambda s=scene: controller.show_frame(s))
            btn.pack(side="left", padx=5)

        # Right-aligned config and help
        right_side = ctk.CTkFrame(nav_bar, fg_color="transparent")
        right_side.pack(side="right")

        config_button = ctk.CTkButton(right_side, text="Config", width=30)
        config_button.pack(side="left", padx=5)

        help_button = ctk.CTkButton(right_side, text="?", width=30)
        help_button.pack(side="left")

        # === Main Content Form ===
        form_frame = ctk.CTkFrame(self, fg_color="transparent")
        form_frame.pack(pady=60)

        def encrypt_file():
            file_path = file_entry.get()
            if not file_path:
                messagebox.showwarning("No File", "Please select a file first.")
                return
            else:
                try:
                    result = fe.encrypt(file_path)
                    messagebox.showinfo("Success", "File encrypted successfully." if result is None else result)
                except Exception as e:
                    messagebox.showerror("Error", f"Encryption Failed: {e}")

        def decrypt_file():
            file_path = file_entry.get()
            if not os.path.exists(file_path):
                messagebox.showerror("Error", "File does not exist.")
                return
            try:
                result = fe.decrypt(file_path)
                messagebox.showinfo("Success", "File decrypted." if result is None else result)
            except Exception as e:
                messagebox.showerror("Error", f"Decryption Failed: {e}")

        def browse_file():
            file_path = filedialog.askopenfilename(
                title="Select a file",
                filetypes=[("All files", "*.*"), ("Text files", "*.txt")]
            )
            if file_path:
                file_entry.delete(0, "end")
                file_entry.insert(0, file_path)

        # Select File Row
        file_label = ctk.CTkLabel(form_frame, text="Select File", anchor="w")
        file_label.grid(row=0, column=0, sticky="w", pady=5)
        file_entry = ctk.CTkEntry(form_frame, width=300)
        file_entry.grid(row=1, column=0, sticky="w", pady=5)
        file_browse = ctk.CTkButton(form_frame, text="Browse", width=80, command=browse_file)
        file_browse.grid(row=1, column=1, padx=10)

        # Encrypt / Decrypt Buttons
        action_frame = ctk.CTkFrame(self, fg_color="transparent")
        action_frame.pack(pady=30)

        encrypt_btn = ctk.CTkButton(action_frame, text="Encrypt", width=100, command=encrypt_file)
        encrypt_btn.pack(side="left", padx=10)

        decrypt_btn = ctk.CTkButton(action_frame, text="Decrypt", width=100, command=decrypt_file)
        decrypt_btn.pack(side="left", padx=10)

if __name__ == "__main__":
    app = App()
    app.mainloop()