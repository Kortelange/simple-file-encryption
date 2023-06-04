import unittest
from os import urandom
from encryption_functions import encrypt, decrypt, derive_key
from cryptography.fernet import InvalidToken


class TestEncryption(unittest.TestCase):
    def test_encryption_and_decryption(self):
        password = "password".encode()
        salt = urandom(16)  # create a random salt
        key = derive_key(password, salt)
        plaintext = "Hello, world!"
        ciphertext = encrypt(key, plaintext)
        decrypted = decrypt(key, ciphertext)
        self.assertEqual(plaintext, decrypted)
        # Test decryption with wrong key
        wrong_password = "wrongpassword".encode()
        wrong_key = derive_key(wrong_password, salt)
        with self.assertRaises(InvalidToken):
            decrypt(wrong_key, ciphertext)