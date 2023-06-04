from os import urandom
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64
import argparse


def derive_key(password, salt):
    """
    Derives a symmetric encryption key from a password and a salt using the PBKDF2-HMAC-SHA256 key derivation function.

    :param password: The password for key derivation.
    :param salt: The salt for key derivation.
    :return: The derived symmetric encryption key.
    """
    password = password.encode()
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend())
    return base64.urlsafe_b64encode(kdf.derive(password))


def encrypt(key, plaintext):
    """
    Encrypts a plaintext using a symmetric encryption key.

    :param key: The symmetric encryption key.
    :param plaintext: The plaintext to be encrypted.
    :return: The resulting ciphertext.
    """
    cipher_suite = Fernet(key)
    cipher_text = cipher_suite.encrypt(plaintext.encode())
    return cipher_text


def decrypt(key, ciphertext):
    """
    Decrypts a ciphertext using a symmetric encryption key.

    :param key: The symmetric encryption key.
    :param ciphertext: The ciphertext to be decrypted.
    :return: The resulting plaintext.
    """
    cipher_suite = Fernet(key)
    plain_text = cipher_suite.decrypt(ciphertext)
    return plain_text.decode()


def save_encrypted_file(filename, password, plaintext):
    """
    Generates a random salt, derives a key from the password, encrypts the plaintext,
    and then writes the salt and the encrypted ciphertext into the file.

    :param filename: The name of the file
    :param password: The password for encryption
    :param plaintext: The plaintext to be encrypted
    """
    salt = urandom(16)
    key = derive_key(password, salt)
    ciphertext = encrypt(key, plaintext)
    with open(filename, "wb") as file:
        file.write(salt + ciphertext)  # Write salt first, then ciphertext


def open_encrypted_file(filename, password):
    """
    Reads the salt and the encrypted ciphertext from the file, derives the key from the
    salt and password, and then decrypts the ciphertext.

    :param filename: The name of the file
    :param password: The password for decryption
    :return: The decrypted text
    """
    with open(filename, "rb") as file:
        salt = file.read(16)  # Read the first 16 bytes as salt
        ciphertext = file.read()  # Read the rest as ciphertext
    key = derive_key(password, salt)
    plaintext = decrypt(key, ciphertext)
    return plaintext


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Encrypt or decrypt a file.')
    parser.add_argument('filename', help='The name of the file to encrypt or decrypt')
    parser.add_argument('password', help='The password to use for encryption or decryption')
    parser.add_argument('--decrypt', '-d', action='store_true', help='Decrypt the file')
    args = parser.parse_args()

    if args.decrypt:
        print(open_encrypted_file(args.filename, args.password))
    else:
        # We don't have any plaintext to encrypt from the command line
        print("Only decryption is currently supported from the command line.")
