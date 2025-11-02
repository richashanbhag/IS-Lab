import socket
import json
from datetime import datetime
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import base64

HOST = '127.0.0.1'
PORT = 8000

def encrypt_AES(message):
    """Encrypts message using AES-256"""
    key = get_random_bytes(32)
    cipher = AES.new(key, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(message.encode())
    return base64.b64encode(cipher.nonce + tag + ciphertext).decode()

def send_record(record):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((HOST, PORT))
        s.sendall(json.dumps(record).encode())
        s.close()
        print(f"[Client] Record sent for {record['doctor_name']}")
    except Exception as e:
        print("[Client] Error:", e)

def main():
    print("=== Doctor Client ===")

    # Read from input file
    try:
        with open("medical_records.txt", "r") as f:
            lines = f.readlines()
    except FileNotFoundError:
        print("❌ 'medical_records.txt' not found!")
        return

    for line in lines:
        if not line.strip():
            continue
        parts = line.strip().split("|")
        record = {
            "doctor_name": parts[0].split(":")[1].strip(),
            "department": parts[1].split(":")[1].strip(),
            "condition": parts[2].split(":")[1].strip(),
            "notes": encrypt_AES(parts[3].split(":")[1].strip()),
            "timestamp": datetime.utcnow().isoformat() + "Z"
        }
        send_record(record)

if __name__ == "__main__":
    main()
