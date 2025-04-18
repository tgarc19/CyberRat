from cryptography.fernet import Fernet
import os

class FileEncryptor:

    def __init__(self, key_file="key.key"):
        self.key_file = key_file
        self.key = self.get_key()
        self.state = False

    def generate_key(self):
        self.key = Fernet.generate_key()
        with open(self.key_file, "wb") as file:
            file.write(self.key)

    def get_key(self):
        if os.path.exists(self.key_file):
            with open(self.key_file, "rb") as file:
                return file.read()
        else:
            return "No key found."
        
    def update_key(self, file):
        if self.state:
            self.decrypt(file)
            self.generate_key()
            self.encrypt(file)
        else:
            self.generate_key()

    def encrypt(self, file):
        if self.state == False:
            encryptor = Fernet(self.key)
            with open(file, "rb") as file_open:
                clear_text = file_open.read()
            cipher_text = encryptor.encrypt(clear_text)
            with open(file, "wb") as file_open_write:
                file_open_write.write(cipher_text)
            self.state = True
        else:
            return "File already encrypted."

    def decrypt(self, file):
        if self.state:
            decryptor = Fernet(self.key)
            with open(file, "rb") as file_open:
                cipher_text = file_open.read()
            clear_text = decryptor.decrypt(cipher_text)
            with open(file, "wb") as file_open_write:
                file_open_write.write(clear_text)
            self.state = False
        else:
            return "File not encrypted."