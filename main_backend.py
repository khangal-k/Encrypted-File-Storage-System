import os
import uuid
import datetime
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
STORAGE_PATH = os.path.join(BASE_DIR, "SecureStorage")
ENC_PATH = os.path.join(STORAGE_PATH, "Encrypted")
KEY_PATH = os.path.join(STORAGE_PATH, "Keys")

os.makedirs(ENC_PATH, exist_ok=True)
os.makedirs(KEY_PATH, exist_ok=True)

LOG_FILE = os.path.join(STORAGE_PATH, "activity.log")

def log_event(action, details=""):
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(LOG_FILE, "a", encoding="utf-8") as log:
        log.write(f"[{timestamp}] {action}: {details}\n")

def derive_key(password: str) -> bytes:
    digest = hashes.Hash(hashes.SHA256())
    digest.update(password.encode())
    return digest.finalize()

#FILE OPERATIONS FOR UI

def store_file_backend(file_path, password):
    if not os.path.isfile(file_path):
        return False, "File not found."

    with open(file_path, "rb") as f:
        file_bytes = f.read()

    key = derive_key(password)
    iv = os.urandom(16)

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    pad_len = 16 - (len(file_bytes) % 16)
    file_bytes += bytes([pad_len]) * pad_len

    encrypted = encryptor.update(file_bytes) + encryptor.finalize()
    file_id = uuid.uuid4().hex

    with open(os.path.join(ENC_PATH, file_id), "wb") as f:
        f.write(encrypted)

    with open(os.path.join(KEY_PATH, file_id), "wb") as f:
        f.write(iv)

    log_event("ENCRYPTED", f"{file_path} → ID: {file_id}")

    return True, file_id


def retrieve_file_backend(file_id, password, output_path):
    enc_file = os.path.join(ENC_PATH, file_id)
    iv_file = os.path.join(KEY_PATH, file_id)

    if not os.path.isfile(enc_file) or not os.path.isfile(iv_file):
        return False, "File ID not found."

    with open(enc_file, "rb") as f:
        encrypted = f.read()

    with open(iv_file, "rb") as f:
        iv = f.read()

    key = derive_key(password)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()

    try:
        decrypted = decryptor.update(encrypted) + decryptor.finalize()
    except:
        return False, "Incorrect password."

    pad_len = decrypted[-1]
    decrypted = decrypted[:-pad_len]

    with open(output_path, "wb") as f:
        f.write(decrypted)

    log_event("DECRYPTED", f"ID: {file_id} → {output_path}")

    return True, "File successfully decrypted."


def list_files_backend():
    return os.listdir(ENC_PATH)


def delete_file_backend(file_id):
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

    return deleted


def delete_all_backend():
    for f in os.listdir(ENC_PATH):
        os.remove(os.path.join(ENC_PATH, f))
    for f in os.listdir(KEY_PATH):
        os.remove(os.path.join(KEY_PATH, f))
    log_event("DELETED_ALL", "All encrypted files removed")
    return True
