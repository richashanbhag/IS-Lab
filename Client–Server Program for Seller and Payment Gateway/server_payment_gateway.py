# Client (Seller):
# Each seller performs transactions.
# Uses Paillier to encrypt each amount.
# Uses homomorphic addition to compute total (encrypted sum).
# Decrypts to verify total amount.
# Prepares a detailed summary.
# Uses SHA-256 hash of the summary.
# Signs it with RSA private key.
# Sends {summary, signature, public_key} to server.
#
# Server (Payment Gateway)
# Receives the seller’s data.
# Recomputes the SHA-256 hash.
# Uses seller’s public key to verify signature.
# Displays:
# Seller Name
# Transactions
# Encrypted + Decrypted Totals
# Signature Verification


import socket
import hashlib
import pickle

from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15

def start_server(host='127.0.0.1', port=5000):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((host, port))
    server.listen(2)
    print(f"[*] Payment Gateway running on {host}:{port}\n")

    while True:
        conn, addr = server.accept()
        print(f"[+] Connected with Seller at {addr}")

        import pickle

        data = b""
        while True:
            packet = conn.recv(4096)
            if not packet:
                break
            data += packet

        summary, signature, pubkey_data = pickle.loads(data)

        # Recreate RSA public key
        pubkey = RSA.import_key(pubkey_data)

        # Recompute hash of summary
        hash_val = hashlib.sha256(summary.encode()).digest()

        hash_obj = SHA256.new(summary.encode())

        try:
            pkcs1_15.new(pubkey).verify(hash_obj, signature)
            verification_status = "VALID "
        except (ValueError, TypeError):
            verification_status = "INVALID "

        # Display transaction summary and result
        print("====== Transaction Summary Received ======")
        print(summary)
        print(f"\nDigital Signature Verification: {verification_status}")
        print("==========================================\n")

        conn.close()

if __name__ == "__main__":
    start_server()
