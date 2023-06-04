import os
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64


def derive_key(password, salt):
    password = password.encode()
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend())
    return base64.urlsafe_b64encode(kdf.derive(password))


def encrypt(key, plaintext):
    # Encryption logic
    cipher_suite = Fernet(key)
    cipher_text = cipher_suite.encrypt(plaintext.encode())
    return cipher_text


def decrypt(key, ciphertext):
    # Decryption logic
    cipher_suite = Fernet(key)
    plain_text = cipher_suite.decrypt(ciphertext)
    return plain_text.decode()


def save_encrypted_file(filename, key, plaintext):
    ciphertext = encrypt(key, plaintext)
    with open(filename, 'wb') as f:
        f.write(ciphertext)


def open_encrypted_file(filename, key):
    with open(filename, 'rb') as f:
        ciphertext = f.read()
    return decrypt(key, ciphertext)

