import customtkinter as ctk

root = ctk.CTk()
root.geometry("750x450")
root.title("Cyber Rat")

#Setup Screen
#TODO determine orientation, pack, grid, etc...
title_label = ctk.CTkLabel(root, text="Cyber Rat", font=ctk.CTkFont(size=128))

direction_label = ctk.CTkLabel(root, text="Choose File Location", font=ctk.CTkFont(size=32))

browse_button = ctk.CTkButton(root, text="Browse", width=113, command=browse_event)

def browse_event():
    print("Pull Up File Exployer to put install location")

root.mainloop() 