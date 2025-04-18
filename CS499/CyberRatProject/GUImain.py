import customtkinter as ctk

class App(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("Cyber Rat")
        self.geometry("750x450")
        #TODO put configures here for positioning on frame (Don't know if grid, pack or something else is better)

        #---ELEMENTS---
        title_label = ctk.CTkLabel(self, text="Cyber Rat", font=ctk.CTkFont(size=128))

        #Buttons TODO pack or grid buttons (can pack to test)
        self.encrypt_button = ctk.CTkButton(self, text="Encrypt", command=encrypt_event)
        #self.encrypt_button.pack
        self.nmap_button = ctk.CTkButton(self, text="Scan", command=nmap_event)
        self.password_manager_button = ctk.CTkButton(self, text="PassManage", command=password_event)


        #event handling TODO change frames with the bottom classes (must forget current frame to swap)
        def encrypt_event():
            print("encrypting")
        
        def nmap_event():
            print("scanning")
        
        def password_event():
            print("passwording")

    #--SCENES--
    #TODO create tabs anchored in top left in each scene
    class NmapScene(ctk.CTk):
        def __init__(self):
            self.title("Cyber Rat Scapy")
            self.geometry("1440x1024")

    class PasswordScene(ctk.CTk):
        def __init__(self):
            self.title("Cyber Rat Passwords")
            self.geometry("1440x1024")
    
    class FileEncryptScene(ctk.CTk):
        def __init__(self):
            self.title("Cyber Rat File Encrypt")
            self.geometry("1440x1024")
    
    class PopUpPasswordScene(ctk.CTk):
        def __init__(self):
            self.geometry("400x200")


app = App()
app.mainloop() 

