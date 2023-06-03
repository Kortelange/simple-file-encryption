import tkinter as tk
from tkinter import filedialog
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes

class TextEditor:
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
        password = tk.simpledialog.askstring("Password", "Enter a password", show="*")
        if not password:
            tk.messagebox.showerror("Error", "Password cannot be empty.")
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
        password = tk.simpledialog.askstring("Password", "Enter a password", show="*")
        if not password:
            tk.messagebox.showerror("Error", "Password cannot be empty.")
            return

        file_path = filedialog.askopenfilename(defaultextension=".enc")
        if not file_path:
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
