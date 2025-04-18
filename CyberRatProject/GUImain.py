from scapy.all import ARP, Ether, srp
import customtkinter as ctk
import CyberRatProject.PasswordManager as pm
import random
import string
import threading

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
        scroll_frame = ctk.CTkScrollableFrame(self, width=800, height=350)
        scroll_frame.pack(pady=10)

        self.populate_password_list(scroll_frame)

        # === ADD Button ===
        add_button = ctk.CTkButton(self, text="ADD", width=200, command=self.open_add_popup)
        add_button.pack(pady=20)

    def open_add_popup(self):
        popup = ctk.CTkToplevel(self)
        popup.title("Add Password")
        popup.geometry("400x250")
        popup.grab_set()  # Makes it modal

        # === Entry frame ===
        input_frame = ctk.CTkFrame(popup)
        input_frame.pack(expand=True, fill="both", padx=20, pady=20)

        # URL entry
        url_label = ctk.CTkLabel(input_frame, text="Enter URL")
        url_label.pack(anchor="w", pady=(0, 5))
        url_entry = ctk.CTkEntry(input_frame, width=300)
        url_entry.insert(0, "https://")  # Pre-fill
        url_entry.pack(pady=5)

        # Password row
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

        # Add button
        add_btn = ctk.CTkButton(input_frame, text="ADD", width=200,
                                command=lambda: self.save_password(url_entry.get(), password_entry.get(), popup))
        add_btn.pack(pady=15)

    def generate_password(self, length=12):
        characters = string.ascii_letters + string.digits + "!@#$%^&*()"
        return ''.join(random.choices(characters, k=length))

    def save_password(self, url, password, popup_window):
        print(f"Saved: {url} → {password}")
        popup_window.destroy()
        
    def populate_password_list(self, parent):
        entries = [
            ("github.com", "user1", "hunter2"),
            ("chat.openai.com", "openaiUser", "password123"),
            ("cyberrat.local", "admin", "rat4life"),
        ]

        for site, username, password in entries:
            entry_frame = HoverFrame(parent)
            entry_frame.pack(fill="x", pady=2, padx=5)

            # Always-visible labels
            site_label = ctk.CTkLabel(entry_frame, text=site, width=200, anchor="w")
            site_label.grid(row=0, column=0, sticky="w", padx=5)

            user_label = ctk.CTkLabel(entry_frame, text=username, width=150, anchor="w")
            user_label.grid(row=0, column=1, sticky="w", padx=5)

            password_label = ctk.CTkLabel(entry_frame, text=password, width=200, anchor="w")
            password_label.grid(row=0, column=2, sticky="w", padx=5)

            # Hover-visible buttons
            copy_button = ctk.CTkButton(entry_frame, text="Copy", width=70)
            edit_button = ctk.CTkButton(entry_frame, text="Edit", width=70)
            delete_button = ctk.CTkButton(entry_frame, text="🗑️", width=30, fg_color="red", text_color="white")

            copy_button.grid(row=0, column=3, padx=5)
            edit_button.grid(row=0, column=4, padx=5)
            delete_button.grid(row=0, column=5, padx=5)

            # Only buttons are hover widgets now
            entry_frame.set_hover_widgets([
                copy_button, edit_button, delete_button
            ])


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

        # Select File Row
        file_label = ctk.CTkLabel(form_frame, text="Select File", anchor="w")
        file_label.grid(row=0, column=0, sticky="w", pady=5)
        file_entry = ctk.CTkEntry(form_frame, width=300)
        file_entry.grid(row=1, column=0, sticky="w", pady=5)
        file_browse = ctk.CTkButton(form_frame, text="Browse", width=80)
        file_browse.grid(row=1, column=1, padx=10)

        # Encryption Styles Row
        style_label = ctk.CTkLabel(form_frame, text="Encryption Styles", anchor="w")
        style_label.grid(row=2, column=0, sticky="w", pady=(20, 5))
        style_entry = ctk.CTkEntry(form_frame, width=300)
        style_entry.grid(row=3, column=0, sticky="w", pady=5)
        style_browse = ctk.CTkButton(form_frame, text="Browse", width=80)
        style_browse.grid(row=3, column=1, padx=10)

        # Encrypt / Decrypt Buttons
        action_frame = ctk.CTkFrame(self, fg_color="transparent")
        action_frame.pack(pady=30)

        encrypt_btn = ctk.CTkButton(action_frame, text="Encrypt", width=100)
        encrypt_btn.pack(side="left", padx=10)

        decrypt_btn = ctk.CTkButton(action_frame, text="Decrypt", width=100)
        decrypt_btn.pack(side="left", padx=10)

if __name__ == "__main__":
    app = App()
    app.mainloop()


