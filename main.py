import os
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import getpass
import pickle

# -----------------------------------------------------------------
# encrypt using password and salt
# -----------------------------------------------------------------
def encrypt_secret(password, secret):
    # generate a random salt
    salt = os.urandom(16)
    # create a key derivation function (KDF) using PBKDF2
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=390000)
    # derive a key from the password
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    # create a Fernet symmetric encryption cipher using the key
    f = Fernet(key)
    # encrypt the secret
    encrypted_secret = f.encrypt(secret.encode())
    return salt, encrypted_secret

# -----------------------------------------------------------------
# decrypt a secret using a password and salt
# -----------------------------------------------------------------
def decrypt_secret(password, salt, encrypted_secret):
    # create a key using PBKDF2 with the provided salt
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=390000)
    # derive a key from the password using the same salt
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    # create a Fernet symmetric encryption cipher using the key
    f = Fernet(key)
    # decrypt the secret
    decrypted_secret = f.decrypt(encrypted_secret).decode()
    return decrypted_secret

# -----------------------------------------------------------------
# save passwords dictionary to a file using pickle
# -----------------------------------------------------------------
def save_passwords_to_file(passwords, filename):
    with open(filename, 'wb') as file:
        pickle.dump(passwords, file)

# -----------------------------------------------------------------
# load passwords dictionary from pickle
# -----------------------------------------------------------------
def load_passwords_from_file(filename):
    if not os.path.exists(filename):
        # if file doesn't exist - return empty dict
        return {}
    with open(filename, 'rb') as file:
        return pickle.load(file)

# -----------------------------------------------------------------
# get user input to either encrypt or decrypt
# -----------------------------------------------------------------
def prompt_action():
    while True:
        action = input("Do you want to encrypt or decrypt? (E/D): ").strip().lower()
        if action in ['e', 'encrypt', 'd', 'decrypt']:
            return action
        else:
            print("Invalid input. Please enter 'E' for encrypt or 'D' for decrypt.")


def main():
    filename = "passwords.pkl"  # to store passwords
    passwords = load_passwords_from_file(filename)  # load passwords from file
    action = prompt_action()  # get user prompt for action
    
    # if prompt is to encrypt
    if action.startswith('e'):
        password = getpass.getpass("Enter your password: ")  # ask user for password
        secret = input("Enter your secret: ")  # get secret from user
        salt, encrypted_secret = encrypt_secret(password, secret)  # Encrypt the secret
        passwords[password] = (salt, encrypted_secret)  # store encrypted secret in dictionary
        save_passwords_to_file(passwords, filename)  # save dictionary to pickle file
        print("Encrypted secret saved.")

    # if prompt is to decrypt
    elif action.startswith('d'):
        password = getpass.getpass("Please enter your password: ")  # ask user for password
        # check if password is in dictionary
        if password in passwords:
            salt, encrypted_secret = passwords[password]  # get salt and encrypted secret
            decrypted_secret = decrypt_secret(password, salt, encrypted_secret)  # decrypt the secret
            print("The decrypted secret is:", decrypted_secret)  # print result
        # if password is not found in dictionary
        else:
            print("Password not found.")  # Print error message
    
    # if invalid action aka user input is not 'e' or 'd'
    else:
        print("Invalid action.")

if __name__ == "__main__":
    main()
