import os
import uuid
import getpass
import datetime
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

#OLDER SETUP
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
STORAGE_PATH = os.path.join(BASE_DIR, "SecureStorage")
ENC_PATH = os.path.join(STORAGE_PATH, "Encrypted")
KEY_PATH = os.path.join(STORAGE_PATH, "Keys")

os.makedirs(ENC_PATH, exist_ok=True)

os.makedirs(KEY_PATH, exist_ok=True)

#logging systems
LOG_FILE = os.path.join(STORAGE_PATH, "activity.log")

def log_event(action, details=""):
    """Write activity logs with timestamps."""
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(LOG_FILE, "a", encoding="utf-8") as log:
        log.write(f"[{timestamp}] {action}: {details}\n")

#utility
def derive_key(password: str) -> bytes:
    """Derive AES key using SHA-256."""
    digest = hashes.Hash(hashes.SHA256())
    digest.update(password.encode())
    return digest.finalize()  # 32 bytes (AES-256)

def get_password_masked(prompt="Enter password: "):
    """Secure hidden password input."""
    return getpass.getpass(prompt)

#encryption

def store_file():
    file_path = input("\nEnter full file path to store: ").strip().strip('"')

    if not os.path.isfile(file_path):
        print("File not found.")
        return

    password = get_password_masked("Enter password for encryption: ")
    if password == "":
        print("Password cannot be empty.")
        return

    with open(file_path, "rb") as f:
        file_bytes = f.read()

    print(f"Read {len(file_bytes)} bytes.")

    key = derive_key(password)
    iv = os.urandom(16)

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    # PKCS7 padding
    pad_len = 16 - (len(file_bytes) % 16)
    file_bytes += bytes([pad_len]) * pad_len

    encrypted = encryptor.update(file_bytes) + encryptor.finalize()

    file_id = uuid.uuid4().hex

    with open(os.path.join(ENC_PATH, file_id), "wb") as f:
        f.write(encrypted)

    with open(os.path.join(KEY_PATH, file_id), "wb") as f:
        f.write(iv)

    log_event("ENCRYPTED", f"{file_path} → ID: {file_id}")

    print("\nFile encrypted and stored.")
    print(f"File ID: {file_id}")
    print(f"Encrypted size: {len(encrypted)} bytes")

#decryption
def retrieve_file():
    file_id = input("\nEnter File ID to retrieve: ").strip()

    enc_file = os.path.join(ENC_PATH, file_id)
    iv_file = os.path.join(KEY_PATH, file_id)

    if not os.path.isfile(enc_file) or not os.path.isfile(iv_file):
        print("Encrypted file or key not found.")
        return

    password = get_password_masked("Enter password for decryption: ")

    with open(enc_file, "rb") as f:
        encrypted = f.read()

    with open(iv_file, "rb") as f:
        iv = f.read()

    key = derive_key(password)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()

    decrypted = decryptor.update(encrypted) + decryptor.finalize()

    #Removes PKCS7 padding
    pad_len = decrypted[-1]
    decrypted = decrypted[:-pad_len]

    out_path = input("Enter output file path: ").strip().strip('"')
    if out_path == "":
        print("Invalid path.")
        return

    with open(out_path, "wb") as f:
        f.write(decrypted)

    log_event("DECRYPTED", f"ID: {file_id} → output: {out_path}")

    print("File successfully decrypted and saved.")

#list, delete, deleteall
def list_files():
    files = os.listdir(ENC_PATH)
    print("\nStored File IDs:")
    if not files:
        print("(none)")
    for f in files:
        print(f)

def delete_file():
    file_id = input("\nEnter File ID to delete: ").strip()

    enc_file = os.path.join(ENC_PATH, file_id)
    iv_file = os.path.join(KEY_PATH, file_id)

    deleted = False

    if os.path.exists(enc_file):
        os.remove(enc_file)
        deleted = True
    if os.path.exists(iv_file):
        os.remove(iv_file)
        deleted = True

    if deleted:
        log_event("DELETED", f"ID: {file_id}")

    print("File deleted." if deleted else "File ID not found.")

def delete_all_files():
    confirm = input("\nDelete ALL files? (yes/no): ").lower()
    if confirm == "yes":
        for f in os.listdir(ENC_PATH):
            os.remove(os.path.join(ENC_PATH, f))
        for f in os.listdir(KEY_PATH):
            os.remove(os.path.join(KEY_PATH, f))
        log_event("DELETED_ALL", "All encrypted files removed")
        print("All files deleted.")
    else:
        print("Cancelled.")

#mainmenu
def main():
    while True:
        print("\nCryptographic File Storage System")
        print("================================")
        print("1. Store a file")
        print("2. Retrieve a file")
        print("3. List stored files")
        print("4. Delete a file")
        print("5. Delete ALL files")
        print("0. Exit")

        choice = input("\nChoose: ")

        if choice == "1":
            store_file()
        elif choice == "2":
            retrieve_file()
        elif choice == "3":
            list_files()
        elif choice == "4":
            delete_file()
        elif choice == "5":
            delete_all_files()
        elif choice == "0":
            break
        else:
            print("Invalid choice.")

        input("\nPress Enter to continue...")

if __name__ == "__main__":
    main()
11