# Simple File Encryption

A simple file encryption/decryption application using Python and Tkinter. It allows you to write text in a GUI text editor, encrypt it with a password and save it to a file. You can also open and decrypt previously encrypted files.

The application uses a password-based key derivation function (PBKDF2) with a random salt to securely generate an encryption key from a password. The encryption is performed using the Fernet symmetric encryption method.

The encrypted file format is simple: the first 16 bytes are the salt, and the rest is the ciphertext.

## Installation

1. Clone this repository: `git clone https://github.com/kortelange/simple-file-encryption`
2. Navigate to the repository folder: `cd simple-file-encryption`
3. Install the required Python packages: `pip install -r requirements.txt`
4. Run the application: `python text_editor.py`

## Usage

### GUI Text Editor

1. Run `python text_editor.py` to start the application.
2. To open an encrypted file, select `File > Open` from the menu, select the file, and enter the password.
3. To save the current text to an encrypted file, select `File > Save`, enter a password, and select the file to save to.

### Command Line

1. To decrypt a file from the command line, run `python encryption_functions.py -d filename password`, replacing `filename` with the name of the file and `password` with the password.

## Example

We have included a text as an encrypted file called `test_file.txt`. The password is `password`. Here is how you can decrypt it from the command line:

```bash
python encryption_functions.py -d test_file.txt password
