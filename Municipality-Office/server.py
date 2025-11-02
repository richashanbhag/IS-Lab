"""
============================================================
 Project: Municipality–Office Secure Communication
 -----------------------------------------------------------
 Description:
 Municipality (server) receives encrypted ward data
 from the Office (client).

 Security Flow:
 - Data encrypted with AES-256
 - File integrity ensured via SHA-256 hash
 - ECDSA signature guarantees authenticity
 - Server verifies signature & hash
 - Allows ward-based search & tax aggregation
 ============================================================
"""

import socket
import json
import hashlib
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.PublicKey import ECC
from Crypto.Signature import DSS
from base64 import b64decode


# -------------------- AES Decryption --------------------
def decrypt_aes(ciphertext_b64, key, iv_b64):
    ciphertext = b64decode(ciphertext_b64)
    iv = b64decode(iv_b64)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = cipher.decrypt(ciphertext)
    return plaintext.rstrip(b'\0').decode()


# -------------------- Server Code --------------------
def start_server():
    host = '127.0.0.1'
    port = 6000
    print("\n=== Municipality (Server) ===")
    s = socket.socket()
    s.bind((host, port))
    s.listen(1)
    print("Waiting for connection from Office...")

    conn, addr = s.accept()
    print("Connected from:", addr)

    data = conn.recv(8192).decode()
    packet = json.loads(data)
    conn.close()

    print("\nData received successfully from Office.")

    # Extract fields
    encrypted_data = packet["encrypted_data"]
    iv = packet["iv"]
    hash_value = packet["hash"]
    signature_b64 = packet["signature"]
    ecc_pubkey_pem = packet["public_key"]
    aes_key_b64 = packet["aes_key"]

    # Rebuild keys
    ecc_pubkey = ECC.import_key(ecc_pubkey_pem)
    verifier = DSS.new(ecc_pubkey, 'fips-186-3')
    aes_key = hashlib.sha256(aes_key_b64.encode()).digest()

    # Verify signature
    msg_hash = SHA256.new(hash_value.encode())
    from base64 import b64decode
    try:
        verifier.verify(msg_hash, b64decode(signature_b64))
        print("\n✅ ECDSA Signature Verified. Data is Authentic.")
    except ValueError:
        print("\n❌ Signature Verification Failed! Possible tampering.")
        return

    # Decrypt data
    decrypted_content = decrypt_aes(encrypted_data, aes_key, iv)
    print("\nDecrypted Office Data:\n", decrypted_content)

    # Verify hash integrity
    computed_hash = hashlib.sha256(decrypted_content.encode()).hexdigest()
    if computed_hash == hash_value:
        print("\n✅ Hash Verified. Data Integrity Intact.")
    else:
        print("\n❌ Hash Mismatch! File may be corrupted.")

    # --- Municipality Menu ---
    while True:
        print("\n--- Municipality Menu ---")
        print("1. Search Ward Number")
        print("2. Aggregate Tax")
        print("3. Exit")
        choice = input("Enter your choice: ")

        if choice == '1':
            ward = input("Enter ward number to search: ").strip()
            found = False
            print("\nMatching Records:")
            for line in decrypted_content.split('\n'):
                if f"Ward:{ward}" in line:
                    print(" -", line)
                    found = True
            if not found:
                print("No records found for this ward.")

        elif choice == '2':
            total_tax = 0
            for line in decrypted_content.split('\n'):
                if "Tax:" in line:
                    try:
                        tax_val = int(line.split("Tax:")[1].split("|")[0].strip())
                        total_tax += tax_val
                    except:
                        pass
            print(f"\n💰 Total Aggregated Tax: {total_tax}")

        elif choice == '3':
            print("Exiting Municipality Server...")
            break
        else:
            print("Invalid choice!")


if __name__ == "__main__":
    start_server()
