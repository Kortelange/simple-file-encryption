# password_dialog.py
import tkinter as tk
from tkinter import messagebox


class PasswordDialog(tk.simpledialog.Dialog):
    """
    A dialog box for entering and confirming a password.

    This class extends tkinter.simpledialog.Dialog, overriding the body,
    validate, and apply methods. The Dialog class automatically calls
    validate when the user tries to close the dialog, and if validate
    returns True, it calls apply and then closes the dialog.

    Methods:
    body(master): creates the dialog's interface.
    validate(): checks if the entered passwords match.
    apply(): stores the password for later retrieval.
    """
    def body(self, master):
        """
        Create the dialog's interface.

        Parameters:
        master (tkinter.Tk): The parent window of the dialog.

        Returns:
        tkinter.Entry: The first password entry field.
        """
        tk.Label(master, text="Enter a password:").grid(row=0)
        tk.Label(master, text="Confirm password:").grid(row=1)

        self.password_entry1 = tk.Entry(master, show="*")
        self.password_entry2 = tk.Entry(master, show="*")

        self.password_entry1.grid(row=0, column=1)
        self.password_entry2.grid(row=1, column=1)

        return self.password_entry1

    def validate(self):
        """
        Check if the entered passwords match.

        Returns:
        bool: True if the passwords match, False otherwise.
        """
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
        """
        Store the password for later retrieval.
        """
        self.result = self.password_entry1.get()
