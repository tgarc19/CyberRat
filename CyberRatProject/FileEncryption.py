from cryptography.fernet import Fernet
import os

class FileEncryptor:
    def __init__(self, key_file="key.key"):
        self.key_file = key_file
        self.key = self.load_or_generate_key()

    def load_or_generate_key(self):
        if os.path.exists(self.key_file):
            with open(self.key_file, "rb") as f:
                return f.read()
        else:
            key = Fernet.generate_key()
            with open(self.key_file, "wb") as f:
                f.write(key)
            return key

    def regenerate_key(self):
        key = Fernet.generate_key()
        with open(self.key_file, "wb") as f:
            f.write(key)
        self.key = key

    def encrypt_file(self, file_path):
        try:
            with open(file_path, "rb") as f:
                data = f.read()

            fernet = Fernet(self.key)
            encrypted = fernet.encrypt(data)

            with open(file_path, "wb") as f:
                f.write(encrypted)

            return True, "File encrypted successfully."
        except Exception as e:
            return False, f"Encryption failed: {e}"

    def decrypt_file(self, file_path):
        try:
            with open(file_path, "rb") as f:
                data = f.read()

            fernet = Fernet(self.key)
            decrypted = fernet.decrypt(data)

            with open(file_path, "wb") as f:
                f.write(decrypted)

            return True, "File decrypted successfully."
        except Exception as e:
            return False, f"Decryption failed: {e}"

    def update_key_and_reencrypt(self, file_path):
        # Attempts to decrypt first to allow re-keying
        success, _ = self.decrypt_file(file_path)
        if success:
            self.regenerate_key()
            return self.encrypt_file(file_path)
        else:
            return False, "Re-key failed: Unable to decrypt file."