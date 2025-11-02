# # Doctor (Client)
#
# What they do:
#
# Register and submit encrypted medical reports.
#
# Log their medical expenses.
#
# Send all data securely to the auditor/server.
#
# What they use:
#
# AES-256 → Encrypts the actual medical report content.
#
# RSA → Encrypts the AES key before sending it.
#
# ElGamal → Digitally signs the report with a timestamp for authenticity.
#
# Paillier (Homomorphic) → Encrypts the department name (so the auditor can search without decrypting).
#
# RSA-based Homomorphic Encryption → Encrypts expenses (so they can be summed while still encrypted).
#
# Auditor (Server)
#
# What they do:
#
# Receives, stores, and manages all encrypted doctor data.
#
# Searches for doctors by department without decrypting (via Paillier).
#
# Computes total or per-department expenses without decrypting (via homomorphic RSA).
#
# Verifies digital signatures and timestamps (via ElGamal).
#
# Decrypts and audits reports when needed.
#
# Maintains all data securely in a JSON file (persistent storage).

import socket
import json
import threading
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from datetime import datetime
import os

# === Server Setup ===
HOST = '127.0.0.1'
PORT = 8000
DB_FILE = "records.json"
lock = threading.Lock()

# === RSA Key Generation ===
server_key = RSA.generate(2048)
private_key = PKCS1_OAEP.new(server_key)
public_key = server_key.publickey().export_key()

# === Ensure DB file exists ===
if not os.path.exists(DB_FILE):
    with open(DB_FILE, "w") as f:
        json.dump([], f)

def save_to_db(data):
    """Thread-safe JSON storage"""
    with lock:
        # Load safely
        try:
            with open(DB_FILE, "r") as f:
                records = json.load(f)
        except json.JSONDecodeError:
            records = []
        # Append and save
        records.append(data)
        with open(DB_FILE, "w") as f:
            json.dump(records, f, indent=4)

def handle_client(conn, addr):
    try:
        data = conn.recv(4096).decode()
        if not data:
            return
        packet = json.loads(data)
        print(f"[Server] Received record from {packet['doctor_name']} ({packet['department']})")
        save_to_db(packet)
    except Exception as e:
        print(f"[Server] Error: {e}")
    finally:
        conn.close()

def auditor_console():
    while True:
        print("\n=== Auditor Console ===")
        print("1) Search by Department")
        print("2) List All Records")
        print("3) Exit")
        choice = input("Choice: ").strip()

        if choice == "1":
            dept = input("Enter Department: ").strip()
            with lock:
                try:
                    with open(DB_FILE, "r") as f:
                        records = json.load(f)
                except json.JSONDecodeError:
                    records = []
            matches = [r for r in records if r["department"].lower() == dept.lower()]
            print(json.dumps(matches, indent=4) if matches else "No matches found.")

        elif choice == "2":
            with lock:
                try:
                    with open(DB_FILE, "r") as f:
                        records = json.load(f)
                except json.JSONDecodeError:
                    records = []
            print(json.dumps(records, indent=4) if records else "No records yet.")

        elif choice == "3":
            print("Exiting auditor console...")
            break

        else:
            print("Invalid choice. Try again.")

def start_server():
    print("[Server] RSA keys generated.")
    print(f"[Server] Listening on {HOST}:{PORT}")

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind((HOST, PORT))
    s.listen(5)

    threading.Thread(target=auditor_console, daemon=True).start()

    while True:
        conn, addr = s.accept()
        threading.Thread(target=handle_client, args=(conn, addr), daemon=True).start()

if __name__ == "__main__":
    start_server()
