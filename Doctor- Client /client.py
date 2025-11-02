"""
============================================================
 Project: Doctor–Auditor Secure File Sender
 -----------------------------------------------------------
 Description:
 Doctor (client) reads a text file containing details,
 encrypts it using RSA, hashes with MD5, signs using
 ElGamal, and sends it securely to the Auditor (server).
 ============================================================
"""
import socket
import hashlib
import random
import json
from Crypto.Util import number
from Crypto.PublicKey import RSA

# -------------------- ElGamal Digital Signature --------------------
# Generates public and private keys for ElGamal
def elgamal_keygen():
    p = number.getPrime(256)            # large prime
    g = random.randint(2, p - 2)        # generator
    x = random.randint(1, p - 2)        # private key
    y = pow(g, x, p)                    # public key component
    return (p, g, y, x)

# Signs the hashed message using ElGamal
def elgamal_sign(p, g, x, msg_hash_int):
    import math
    while True:
        k = random.randint(2, p - 2)
        if math.gcd(k, p - 1) == 1:     # k must be coprime with (p-1)
            break
    k_inv = pow(k, -1, p - 1)           # modular inverse of k
    r = pow(g, k, p)                    # first signature component
    s = ((msg_hash_int - x * r) * k_inv) % (p - 1)  # second component
    return r, s

# -------------------- RSA for Encryption (Supports Homomorphic Add) --------------------
def rsa_keygen(bits=1024):
    key = RSA.generate(bits)            # generate RSA key pair
    return key, key.publickey()

def rsa_encrypt(pubkey, m):
    return pow(m, pubkey.e, pubkey.n)   # RSA encryption

def rsa_decrypt(privkey, c):
    return pow(c, privkey.d, privkey.n) # RSA decryption

# -------------------- Hash using MD5 --------------------
def md5_hash(data):
    return hashlib.md5(data.encode()).hexdigest()

# -------------------- Doctor (Client) --------------------
def main():
    host = '127.0.0.1'
    port = 5555

    print("\n=== Doctor (Client) ===")

    # Input text file from user
    file_name = input("Enter the text file path: ").strip()
    with open(file_name, 'r') as f:
        content = f.read()

    print("\nFile Content:\n", content)

    # --- Step 1: Generate MD5 Hash of File ---
    hash_value = md5_hash(content)
    print("\nMD5 Hash:", hash_value)

    # --- Step 2: Sign the Hash using ElGamal ---
    p, g, y, x = elgamal_keygen()
    msg_hash_int = int(hash_value, 16)
    r, s = elgamal_sign(p, g, x, msg_hash_int)
    print("\nElGamal Signature: (r={}, s={})".format(r, s))

    # --- Step 3: Encrypt Budgets using RSA ---
    rsa_priv, rsa_pub = rsa_keygen()
    encrypted_data = []
    total_budget_encrypted = 1           # initialize for homomorphic addition

    lines = content.strip().split("\n")

    for line in lines:
        if "budget" in line.lower():     # extract budget from each line
            try:
                amount = int(line.split("Budget:")[1].split("|")[0].strip())
                enc = rsa_encrypt(rsa_pub, amount)
                encrypted_data.append((line, enc))
                # Homomorphic addition = multiplication of ciphertexts mod n
                total_budget_encrypted = (total_budget_encrypted * enc) % rsa_pub.n
            except:
                pass

    # --- Step 4: Prepare Packet for Auditor ---
    packet = {
        "encrypted_data": encrypted_data,
        "total_encrypted_budget": total_budget_encrypted,
        "hash": hash_value,
        "signature": (r, s),
        "elgamal_params": (p, g, y),
        "rsa_pub": (rsa_pub.n, rsa_pub.e),
        "rsa_d": rsa_priv.d
    }

    # --- Step 5: Send Data to Auditor via Socket ---
    s = socket.socket()
    s.connect((host, port))
    s.send(json.dumps(packet).encode())
    print("\nData sent securely to auditor.")
    s.close()


if __name__ == "__main__":
    main()
