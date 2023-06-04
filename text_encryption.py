import tkinter as tk
from tkinter import filedialog
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes
from password_dialog import PasswordDialog


class TextEditor:
    """
    A simple text editor with file encryption and decryption features.

    Attributes:
    root (tkinter.Tk): The root window of the application.
    text_area (tkinter.Text): The text area for editing text.

    Methods:
    open_file(): Opens an encrypted file.
    save_file(): Saves the current text to an encrypted file.
    """
    def __init__(self, root):
        self.text_area = tk.Text(root)
        self.text_area.pack(fill="both", expand=True)

        menu = tk.Menu(root)
        root.config(menu=menu)
        file_menu = tk.Menu(menu)
        menu.add_cascade(label="File", menu=file_menu)
        file_menu.add_command(label="Open", command=self.open_file)
        file_menu.add_command(label="Save", command=self.save_file)

    def save_file(self):
        """
        Encrypts the current text and saves it to a file.

        This method prompts the user for a file path and a password.
        A random salt is generated and combined with the password to derive a key.
        The current text is encrypted with this key, and the resulting ciphertext is written to the selected file,
        preceded by the salt and the iv used for encryption.
        If the user cancels the file dialog or the password dialog, the method returns without saving the file.
        """
        password_dialog = PasswordDialog(root)
        password = password_dialog.result

        if not password:
            return

        file_path = filedialog.asksaveasfilename(defaultextension=".enc")

        if not file_path:
            return

        salt = get_random_bytes(16)
        key = PBKDF2(password, salt, dkLen=16)

        text_to_save = self.text_area.get("1.0", "end-1c").encode()
        cipher = AES.new(key, AES.MODE_CBC)
        ciphertext = cipher.encrypt(pad(text_to_save, AES.block_size))

        with open(file_path, 'wb') as file:
            file.write(salt)
            file.write(cipher.iv)
            file.write(ciphertext)

        tk.messagebox.showinfo("File Saved", "File saved successfully.")

    def open_file(self):
        """
        Opens an encrypted file and displays its decrypted contents in the text area.

        This method prompts the user to select a file, and then prompts for a password.
        The selected file is read as binary and divided into salt, iv, and ciphertext parts.
        The salt and password are used to derive a key, which is then used to decrypt the ciphertext.
        The decrypted plaintext is displayed in the text area.
        If the user cancels the file dialog or the password dialog, the method returns without opening the file.
        """
        file_path = filedialog.askopenfilename(defaultextension=".enc")
        if not file_path:
            return

        password = tk.simpledialog.askstring("Password", "Enter a password", show="*")
        if not password:
            tk.messagebox.showerror("Error", "Password cannot be empty.")
            return

        with open(file_path, 'rb') as file:
            salt = file.read(16)
            iv = file.read(16)
            ciphertext = file.read()

        key = PBKDF2(password, salt, dkLen=16)
        cipher = AES.new(key, AES.MODE_CBC, iv=iv)
        decrypted_text = unpad(cipher.decrypt(ciphertext), AES.block_size).decode()

        self.text_area.delete("1.0", "end")
        self.text_area.insert("1.0", decrypted_text)


if __name__ == "__main__":
    root = tk.Tk()
    app = TextEditor(root)
    root.mainloop()
