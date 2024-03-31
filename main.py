import os
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import getpass

def encrypt_secret(password, secret):
    salt = os.urandom(16)
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=390000)
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    f = Fernet(key)
    encrypted_secret = f.encrypt(secret.encode())
    return salt + encrypted_secret

def decrypt_secret(password, encrypted_secret):
    salt = encrypted_secret[:16]
    encrypted_data = encrypted_secret[16:]
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=390000)
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    f = Fernet(key)
    decrypted_secret = f.decrypt(encrypted_data).decode()
    return decrypted_secret

password = getpass.getpass("Enter your password: ")
secret = input("Enter your secret: ")

encrypted_secret = encrypt_secret(password, secret)

choice = input("Do you want to decrypt the secret? (Y/N): ")
if choice.lower() in ["y", "yes"]:
    check_password = getpass.getpass("Please enter your password: ")
    if check_password == password:
        decrypted_secret = decrypt_secret(password, encrypted_secret)
        print("The decrypted secret is:", decrypted_secret)
    else:
        print("Invalid password, please try again!")
else:
    print("Have a nice day!")
