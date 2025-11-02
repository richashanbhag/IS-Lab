import socket
import hashlib
import pickle

from Crypto.Hash import SHA256
from phe import paillier
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15

def seller_transactions(seller_name, transactions):
    # Paillier Key Generation
    public_key, private_key = paillier.generate_paillier_keypair()

    # Encrypt transactions
    encrypted = [public_key.encrypt(x) for x in transactions]

    # Homomorphic addition of encrypted values
    total_encrypted = sum(encrypted)
    total_decrypted = private_key.decrypt(total_encrypted)

    # Generate transaction summary
    summary = f"\nSeller: {seller_name}\n"
    summary += f"Transactions: {transactions}\n"
    summary += f"Encrypted Transactions: {[str(e.ciphertext()) for e in encrypted]}\n"
    summary += f"Total Encrypted Amount: {total_encrypted.ciphertext()}\n"
    summary += f"Total Decrypted Amount: {total_decrypted}\n"

    return summary

def start_client(host='127.0.0.1', port=5000):
    # Define two sellers with sample transactions
    sellers = {
        "Seller_A": [1200, 1800],
        "Seller_B": [500, 750]
    }

    for seller, txns in sellers.items():
        summary = seller_transactions(seller, txns)

        # Generate RSA keys for signing
        rsa_key = RSA.generate(2048)
        pub_key = rsa_key.publickey().export_key()

        # Hash the summary
        # create hash object
        hash_obj = SHA256.new(summary.encode())

        # sign using private key
        signature = pkcs1_15.new(rsa_key).sign(hash_obj)

        # Package data to send to server
        packet = pickle.dumps((summary, signature, pub_key))

        # Send to payment gateway (server)
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client.connect((host, port))
        client.send(packet)

        print(f"[*] Sent transaction summary for {seller} to Payment Gateway.")
        client.close()

if __name__ == "__main__":
    start_client()
