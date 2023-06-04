import unittest
import os
from os import urandom
import tempfile
from encryption_functions import encrypt, decrypt, derive_key
from cryptography.fernet import InvalidToken
from encryption_functions import save_encrypted_file, open_encrypted_file, encrypt, decrypt, derive_key


class TestEncryption(unittest.TestCase):
    def test_encryption_and_decryption(self):
        password = "password"
        salt = urandom(16)  # create a random salt
        key = derive_key(password, salt)
        plaintext = "Hello, world!"
        ciphertext = encrypt(key, plaintext)
        decrypted = decrypt(key, ciphertext)
        self.assertEqual(plaintext, decrypted)
        # Test decryption with wrong key
        wrong_password = "wrongpassword"
        wrong_key = derive_key(wrong_password, salt)
        with self.assertRaises(InvalidToken):
            decrypt(wrong_key, ciphertext)


class TestFileIO(unittest.TestCase):
    def test_file_io(self):
        # Create a temporary file
        temp = tempfile.NamedTemporaryFile(delete=False)

        try:
            # Generate some content
            plaintext = "Hello, world!"

            # Create a password and salt, then derive a key
            password = "password"

            # Save the encrypted content to the file
            save_encrypted_file(temp.name, password, plaintext)

            # Open the file and read the content
            decrypted = open_encrypted_file(temp.name, password)

            # Make sure the content matches
            self.assertEqual(plaintext, decrypted)
        finally:
            # Clean up the temporary file
            os.remove(temp.name)
