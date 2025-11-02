# Client (Seller):
# Each seller performs transactions.(file)
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
import pickle
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256

def start_server(host='127.0.0.1', port=5000):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((host, port))
    server.listen(5)
    print(f"[*] Payment Gateway running on {host}:{port}\n")

    while True:
        conn, addr = server.accept()
        print(f"[+] Connected with Seller at {addr}")

        data = b""
        while True:
            packet = conn.recv(4096)
            if not packet:
                break
            data += packet
        conn.close()

        summary, signature, pubkey_data = pickle.loads(data)
        print(f"[*] Received transaction summary:\n{summary}")

        # Verify signature
        public_rsa = RSA.import_key(pubkey_data)
        h = SHA256.new(summary.encode())

        try:
            pkcs1_15.new(public_rsa).verify(h, signature)
            print("[+] Digital Signature Verified Successfully.\n")
        except (ValueError, TypeError):
            print("[-] Signature Verification Failed!\n")

if __name__ == "__main__":
    start_server()
