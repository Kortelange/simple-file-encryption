# password_dialog.py
import tkinter as tk
from tkinter import messagebox

class PasswordDialog(tk.simpledialog.Dialog):
    def body(self, master):
        tk.Label(master, text="Enter a password:").grid(row=0)
        tk.Label(master, text="Confirm password:").grid(row=1)

        self.password_entry1 = tk.Entry(master, show="*")
        self.password_entry2 = tk.Entry(master, show="*")

        self.password_entry1.grid(row=0, column=1)
        self.password_entry2.grid(row=1, column=1)

        return self.password_entry1

    def validate(self):
        password1 = self.password_entry1.get()
        password2 = self.password_entry2.get()

        if not password1 or not password2:
            tk.messagebox.showerror("Error", "Password cannot be empty.")
            return False

        if password1 != password2:
            tk.messagebox.showerror("Error", "Passwords do not match.")
            return False

        return True

    def apply(self):
        self.result = self.password_entry1.get()
