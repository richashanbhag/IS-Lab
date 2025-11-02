# server.py
"""
Auditor server with key-distribution handshake and menu:
1) Search branch (by tag) without decrypting
2) Homomorphic add marks and decrypt sum
3) Verify ECDSA signature
4) Decrypt file & show report
5) Exit
"""
import socket, json, base64, hashlib
from phe import paillier
from Crypto.PublicKey import ECC
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Signature import DSS

# Utilities
def derive_aes_key_from_shared(shared_bytes):
    return SHA256.new(shared_bytes).digest()

def aes_decrypt_gcm(ciphertext_b64, key, nonce_b64, tag_b64):
    ct = base64.b64decode(ciphertext_b64)
    nonce = base64.b64decode(nonce_b64)
    tag = base64.b64decode(tag_b64)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    pt = cipher.decrypt_and_verify(ct, tag)
    return pt.decode()

# Server
def start_server(host='127.0.0.1', port=7000):
    print("=== Auditor (Server) ===")
    # Generate Paillier and ECC keys once (server holds private keys)
    paillier_pub, paillier_priv = paillier.generate_paillier_keypair(n_length=1024)
    ecc_priv = ECC.generate(curve='P-256')
    ecc_pub = ecc_priv.public_key()
    ecc_pub_pem = ecc_pub.export_key(format='PEM')

    print("[Server] Paillier (n bits ~= {})".format(paillier_pub.n.bit_length()))
    print("[Server] ECC public key ready (PEM)")

    sock = socket.socket()
    sock.bind((host, port))
    sock.listen(1)
    print(f"[Server] Listening on {host}:{port} ...\n")

    while True:
        conn, addr = sock.accept()
        print("[Server] Connection from", addr)
        # Receive first small request (get_keys) or large packet
        data = conn.recv(8192)
        if not data:
            conn.close()
            continue
        try:
            msg = json.loads(data.decode())
        except:
            conn.close()
            continue

        # If client asks for keys, reply with Paillier n and ECC pub
        if msg.get('type') == 'get_keys':
            reply = {
                'paillier_n': str(paillier_pub.n),
                'ecc_pub_pem': ecc_pub_pem
            }
            conn.send(json.dumps(reply).encode())
            conn.close()
            print("[Server] Sent public keys to client.")
            # Wait for the actual packet connection: client will connect again and send the packet
            conn2, addr2 = sock.accept()
            print("[Server] Packet connection from", addr2)
            # read full packet
            raw = b""
            while True:
                chunk = conn2.recv(8192)
                if not chunk:
                    break
                raw += chunk
            conn2.close()
            try:
                packet = json.loads(raw.decode())
            except Exception as e:
                print("[Server] Failed to parse client packet:", e)
                continue
        else:
            # Client sent packet immediately without handshake
            packet = msg
            conn.close()

        print("[Server] Packet received. Ready for menu operations.\n")

        # Extract expected fields
        enc_file = packet.get('enc_file', {})
        enc_marks_strs = packet.get('enc_marks', [])             # list of ciphertext ints as strings
        enc_marks_product_str = packet.get('enc_marks_product')  # optional combined ciphertext string
        line_tags = enc_file.get('line_tags', [])                # list of SHA256 hex tags per line
        line_refs = enc_file.get('line_refs', [])                # optional plaintext lines (for demo only)
        hash_hex = packet.get('hash', '')
        signature_b64 = packet.get('signature_b64', '')
        client_pub_pem = packet.get('client_pub_pem', '')

        # Reconstruct EncryptedNumber objects using server's paillier_pub
        enc_marks_objs = []
        if enc_marks_strs:
            try:
                from phe import paillier as _pa
                for s_ct in enc_marks_strs:
                    ct_int = int(s_ct)
                    enc_obj = _pa.EncryptedNumber(paillier_pub, ct_int)
                    enc_marks_objs.append(enc_obj)
            except Exception as e:
                print("[Server] Error reconstructing EncryptedNumber:", e)
                enc_marks_objs = []

        # Helpers
        def decrypt_file():
            try:
                eph_pub_pem = enc_file['ephemeral_pub_pem']
                ciphertext_b64 = enc_file['ciphertext_b64']
                nonce_b64 = enc_file['nonce_b64']
                tag_b64 = enc_file['tag_b64']
            except KeyError:
                print("[Server] Missing encrypted file fields.")
                return None
            try:
                eph_pub = ECC.import_key(eph_pub_pem)
                shared_point = eph_pub.pointQ * ecc_priv.d
                x = int(shared_point.x)
                shared_bytes = x.to_bytes((x.bit_length()+7)//8, byteorder='big')
                aes_key = derive_aes_key_from_shared(shared_bytes)
                plaintext = aes_decrypt_gcm(ciphertext_b64, aes_key, nonce_b64, tag_b64)
                return plaintext
            except Exception as e:
                print("[Server] Error decrypting file:", e)
                return None

        def verify_signature():
            # decrypt file to get plaintext first
            plaintext = decrypt_file()
            if plaintext is None:
                print("[Server] Cannot verify signature: file not decrypted.")
                return False

            if not signature_b64 or not client_pub_pem:
                return False

            try:
                pub = ECC.import_key(client_pub_pem)
                verifier = DSS.new(pub, 'fips-186-3')
                # Recompute SHA256 over the plaintext (same as client used)
                msg_hash = SHA256.new(plaintext.encode())
                verifier.verify(msg_hash, base64.b64decode(signature_b64))
                return True
            except Exception as e:
                # print("verify error:", e)
                return False

        def homomorphic_sum_and_decrypt():
            if not enc_marks_objs:
                print("[Server] No encrypted marks to sum.")
                return None, None
            combined = enc_marks_objs[0]
            for enc in enc_marks_objs[1:]:
                combined = combined + enc
            try:
                combined_ct_int = combined.ciphertext()
            except Exception:
                combined_ct_int = None
            try:
                total = paillier_priv.decrypt(combined)
                return combined_ct_int, total
            except Exception as e:
                print("[Server] Error decrypting combined ciphertext:", e)
                return combined_ct_int, None

        # Menu loop
        while True:
            print("\n--- Auditor Menu ---")
            print("1) Search for Branch (without decrypting file)")
            print("2) Add Marks (homomorphic) and decrypt sum")
            print("3) Verify ECDSA Signature")
            print("4) Decrypt file & show report (timestamps etc.)")
            print("5) Exit to wait for next connection")
            choice = input("Enter choice: ").strip()

            if choice == '1':
                key = input("Enter branch/department to search: ").strip().lower()
                tag = hashlib.sha256(key.encode()).hexdigest()
                print("\nMatching entries (by tag):")
                found = False
                for lt, ref in zip(line_tags, line_refs):
                    if lt == tag:
                        print(" -", ref)
                        found = True
                if not found:
                    print("No matches found.")

            elif choice == '2':
                ct_int, total = homomorphic_sum_and_decrypt()
                if ct_int is not None:
                    print("\nEncrypted combined ciphertext (integer):")
                    print(ct_int)
                if total is not None:
                    print("Decrypted sum of marks:", total)
                else:
                    print("Could not decrypt combined sum.")

            elif choice == '3':
                ok = verify_signature()
                print("\nSignature valid?", ok)

            elif choice == '4':
                plaintext = decrypt_file()
                if plaintext:
                    print("\nDecrypted file content:\n")
                    print(plaintext)
                    print("\nParsed lines:")
                    for ln in plaintext.splitlines():
                        print(" -", ln)
                else:
                    print("Could not decrypt file.")
            elif choice == '5':
                print("Return to listening for next connection.")
                break
            else:
                print("Invalid choice.")

        # after exit, go back to listening for next client
        print("\nWaiting for next client...\n")

if __name__ == "__main__":
    start_server()
