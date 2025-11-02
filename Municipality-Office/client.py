"""
============================================================
 Project: Municipality–Office Secure Communication
 -----------------------------------------------------------
 Description:
 Office (client) reads a text file of ward details,
 encrypts it using AES-256, hashes with SHA-256,
 signs hash with ECDSA, and sends securely to
 the Municipality (server).
 ============================================================
"""

import socket
import json
import hashlib
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.PublicKey import ECC
from Crypto.Signature import DSS
from Crypto.Random import get_random_bytes
from base64 import b64encode


# -------------------- AES Encryption --------------------
def encrypt_aes(data, key):
    data_padded = data + (b'\0' * (16 - len(data) % 16))
    iv = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(data_padded)
    return b64encode(ciphertext).decode(), b64encode(iv).decode()


# -------------------- Client Code --------------------
def start_client():
    host = '127.0.0.1'
    port = 6000
    print("\n=== Office (Client) ===")

    # Step 1: Read text file
    file_name = input("Enter the path of the ward data file: ").strip()
    with open(file_name, 'r') as f:
        content = f.read()
    print("\nFile Content:\n", content)

    # Step 2: Hash file using SHA-256
    hash_value = hashlib.sha256(content.encode()).hexdigest()
    print("\nSHA-256 Hash:", hash_value)

    # Step 3: Generate AES-256 key & encrypt data
    aes_key_text = "MunicipalitySecureKey"
    aes_key = hashlib.sha256(aes_key_text.encode()).digest()
    encrypted_data, iv = encrypt_aes(content.encode(), aes_key)

    # Step 4: Generate ECDSA key pair
    ecc_key = ECC.generate(curve='P-256')
    pub_key = ecc_key.public_key()
    signer = DSS.new(ecc_key, 'fips-186-3')

    # Step 5: Sign the hash
    msg_hash = SHA256.new(hash_value.encode())
    signature = signer.sign(msg_hash)

    # Step 6: Create packet for server
    packet = {
        "encrypted_data": encrypted_data,
        "iv": iv,
        "hash": hash_value,
        "signature": b64encode(signature).decode(),
        "public_key": pub_key.export_key(format='PEM'),
        "aes_key": aes_key_text
    }

    # Step 7: Send packet to Municipality
    s = socket.socket()
    s.connect((host, port))
    s.send(json.dumps(packet).encode())
    print("\nData securely sent to Municipality.")
    s.close()


if __name__ == "__main__":
    start_client()
