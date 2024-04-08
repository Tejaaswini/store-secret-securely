# Can You Keep a Secret?

a command-line tool for securely encrypting and decrypting secrets using the Fernet symmetric encryption algorithm.

## Table of Contents

- [Installation](#installation)
- [Usage](#usage)

## Installation

1. clone the repository:

    ```bash
    git clone https://github.com/Tejaaswini/store-secret-securely
    ```

2. navigate to the project directory:

    ```bash
    cd store-secret-securely
    ```

3. ceate a virtual environment:

    ```bash
    python3 -m venv env
    ```

4. activate the virtual environment:

    - on Windows:

    ```bash
    env\Scripts\activate
    ```

    - on macOS and Linux:

    ```bash
    source env/bin/activate
    ```

5. install dependencies:

    ```bash
    pip3 install -r requirements.txt
    ```

## Usage

instructions on how to use the project:

### 1. encrypting a Secret

to encrypt a secret, follow these steps:

1. Run the script `main.py`:

    ```bash
    python3 main.py
    ```

2. When prompted, choose the option to encrypt by entering `E` or `Encrypt`.

3. Enter your password when prompted. The password is used to generate a key for encryption.

4. Enter the secret you want to encrypt when prompted.

5. The encrypted secret will be saved to the `passwords.pkl` file.

### 2. Decrypting a Secret

to decrypt a secret, follow these steps:

1. Run the script `main.py`:

    ```bash
    python3 main.py
    ```

2. When prompted, choose the option to decrypt by entering `D` or `Decrypt`.

3. Enter the password that was used to encrypt the secret when prompted.

4. If the password is correct, the decrypted secret will be displayed.

### Example

encrypting a secret:

```bash
$ python3 main.py
Do you want to encrypt or decrypt? (E/D): E
Enter your password:
Enter your secret: MyEncryptedSecret
Encrypted secret saved.
```

decrypting a secret:
```bash
$ python3 main.py
Do you want to encrypt or decrypt? (E/D): D
Please enter your password:
The decrypted secret is: MyEncryptedSecret
```

