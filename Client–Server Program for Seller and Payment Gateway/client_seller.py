import socket
import pickle
import hashlib
from phe import paillier
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256

def read_transactions(file_path):
    sellers = {}
    with open(file_path, "r") as f:
        for line in f:
            parts = line.strip().split()
            if len(parts) < 2:
                continue
            seller = parts[0]
            amounts = list(map(int, parts[1:]))
            sellers[seller] = amounts
    return sellers

def start_client(host='127.0.0.1', port=5000):
    # Generate Paillier keypair (public, private)
    public_key, private_key = paillier.generate_paillier_keypair()

    # Generate RSA keys for digital signature
    rsa_key = RSA.generate(2048)
    public_rsa = rsa_key.publickey().export_key()

    # Read seller transactions from file
    sellers = read_transactions("transactions.txt")

    for seller, amounts in sellers.items():
        print(f"\nProcessing transactions for {seller}...")
        encrypted = [public_key.encrypt(a) for a in amounts]
        decrypted = [private_key.decrypt(e) for e in encrypted]

        total_enc = encrypted[0]
        for e in encrypted[1:]:
            total_enc = total_enc + e  # Homomorphic addition
        total_dec = private_key.decrypt(total_enc)

        summary = f"Seller: {seller}\n"
        summary += f"Transactions: {amounts}\n"
        summary += f"Encrypted: {[str(e.ciphertext()) for e in encrypted]}\n"
        summary += f"Decrypted: {decrypted}\n"
        summary += f"Total Encrypted: {str(total_enc.ciphertext())}\n"
        summary += f"Total Decrypted: {total_dec}\n"

        # Hash summary
        h = SHA256.new(summary.encode())
        signature = pkcs1_15.new(rsa_key).sign(h)

        # Send everything to server
        data = pickle.dumps((summary, signature, public_rsa))
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client.connect((host, port))
        client.sendall(data)
        client.close()

        print(f"[*] Sent transaction summary for {seller} to Payment Gateway.")

if __name__ == "__main__":
    start_client()
