"""

 Description:
 The Doctor (client) sends a text file containing patient data,
 timestamps, and budgets to the Auditor (server).

 Security Flow:
 - File is encrypted using RSA
 - File is hashed using MD5
 - ElGamal digital signature ensures authenticity
 - RSA homomorphic property allows summing encrypted budgets
   and searching keywords without decrypting
 -----------------------------------------------------------
 Server Functions:
 1. Authenticate doctor
 2. Receive encrypted file
 3. Verify ElGamal signature
 4. Search doctor name / branch in ciphertext (mock demo)
 5. Add encrypted budgets (homomorphic)
 ============================================================
"""


import socket
import json
import hashlib
from Crypto.Util import number

# -------------------- Hash Function --------------------
def md5_hash(data):
    return hashlib.md5(data.encode()).hexdigest()

# -------------------- ElGamal Signature Verification --------------------
def elgamal_verify(p, g, y, r, s, msg_hash_int):
    if not (0 < r < p):
        return False
    # v1 = (y^r * r^s) mod p
    v1 = (pow(y, r, p) * pow(r, s, p)) % p
    # v2 = g^(hash) mod p
    v2 = pow(g, msg_hash_int, p)
    return v1 == v2

# -------------------- Auditor (Server) --------------------
def main():
    host = '127.0.0.1'
    port = 5555

    print("\n=== Auditor (Server) ===")
    s = socket.socket()
    s.bind((host, port))
    s.listen(1)
    print("Waiting for doctor connection...")

    conn, addr = s.accept()
    print("Connected from:", addr)

    # Receive packet from doctor
    data = conn.recv(4096).decode()
    packet = json.loads(data)
    conn.close()
    print("\nData received successfully.")

    # Extract received data
    encrypted_data = packet["encrypted_data"]
    total_encrypted_budget = packet["total_encrypted_budget"]
    hash_value = packet["hash"]
    signature = packet["signature"]
    elgamal_params = packet["elgamal_params"]
    rsa_pub = packet["rsa_pub"]
    rsa_d = packet["rsa_d"]

    rsa_n, rsa_e = rsa_pub
    p, g, y = elgamal_params
    r, s_ = signature

    # --- Menu for Auditor Operations ---
    while True:
        print("\n--- Auditor Menu ---")
        print("1. Search Doctor Branch")
        print("2. Add Budgets (Homomorphic)")
        print("3. Verify Signature")
        print("4. Exit")

        choice = input("Enter your choice: ")

        if choice == '1':
            # Search for a specific branch name without decrypting
            branch = input("Enter branch to search: ").strip().lower()
            found = False
            print("\nMatching Entries:")
            for line, enc in encrypted_data:
                if branch in line.lower():
                    print(" -", line)
                    found = True
            if not found:
                print("No entries found for this branch.")

        elif choice == '2':
            # Homomorphic Addition of Budgets
            print("\nHomomorphically Added (Encrypted) Budget:\n", total_encrypted_budget)
            decrypted_sum = pow(total_encrypted_budget, rsa_d, rsa_n)
            print("Decrypted Total Budget (Approx.):", decrypted_sum)

        elif choice == '3':
            # Verify ElGamal Signature
            msg_hash_int = int(hash_value, 16)
            verified = elgamal_verify(p, g, y, r, s_, msg_hash_int)
            if verified:
                print("\n✅ Signature Verified Successfully. Data is Authentic.")
            else:
                print("\n❌ Signature Verification Failed! Data may be tampered.")

        elif choice == '4':
            print("Exiting Auditor...")
            break

        else:
            print("Invalid choice! Try again.")


if __name__ == "__main__":
    main()
