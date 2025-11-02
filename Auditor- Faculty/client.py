# client.py
"""
Faculty (Client)
- Requests public keys from Auditor (Paillier n and Auditor ECC pub)
- Reads input file lines: "Name | Course | Dept | Marks | Timestamp"
- Creates per-line SHA256 tag for Dept (for searching)
- Encrypts marks using server's Paillier public key (phe.PaillierPublicKey)
- Computes homomorphic combined ciphertext (EncryptedNumber addition)
- ECIES-style encrypt full file using Auditor ECC pub (ephemeral key + ECDH -> AES-GCM)
- SHA256 hash of plaintext, sign with client's ECC key (ECDSA)
- Sends JSON packet to server
"""
import socket, json, base64, hashlib
from phe import paillier
from Crypto.PublicKey import ECC
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Signature import DSS
from Crypto.Random import get_random_bytes

def derive_aes_key_from_shared(shared_bytes):
    return SHA256.new(shared_bytes).digest()

def aes_encrypt_gcm_bytes(plaintext_bytes, key):
    nonce = get_random_bytes(12)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    ct, tag = cipher.encrypt_and_digest(plaintext_bytes)
    return base64.b64encode(ct).decode(), base64.b64encode(nonce).decode(), base64.b64encode(tag).decode()

def get_server_keys(host='127.0.0.1', port=7000):
    s = socket.socket()
    s.connect((host, port))
    req = {'type': 'get_keys'}
    s.send(json.dumps(req).encode())
    data = s.recv(8192)
    s.close()
    return json.loads(data.decode())

def start_client(server_host='127.0.0.1', server_port=7000, input_file='input.txt'):
    print("=== Faculty (Client) ===")
    # 1) Get server public keys
    keys = get_server_keys(server_host, server_port)
    paillier_n = int(keys['paillier_n'])
    auditor_ecc_pub_pem = keys['ecc_pub_pem']

    # Build paillier public object from n
    paillier_pub = paillier.PaillierPublicKey(paillier_n)

    # 2) Read plaintext file
    with open(input_file, 'r') as f:
        plaintext = f.read()
    lines = [ln.strip() for ln in plaintext.splitlines() if ln.strip()]

    # 3) Per-line tags and marks
    line_tags = []
    marks_list = []
    for ln in lines:
        parts = [p.strip() for p in ln.split('|')]
        if len(parts) < 5:
            parts += ['']*(5 - len(parts))
        dept = parts[2]
        try:
            marks = int(parts[3])
        except:
            marks = 0
        tag = hashlib.sha256(dept.lower().encode()).hexdigest()
        line_tags.append(tag)
        marks_list.append(marks)

    # 4) Encrypt marks using server's Paillier public key
    enc_objs = [paillier_pub.encrypt(m) for m in marks_list]  # EncryptedNumber objects
    # convert to ciphertext ints for transmission
    enc_marks_ints = [str(e.ciphertext()) for e in enc_objs]

    # 5) Optionally compute combined ciphertext via EncryptedNumber addition (client-side)
    combined = enc_objs[0]
    for e in enc_objs[1:]:
        combined = combined + e
    combined_ct_int = str(combined.ciphertext())

    # 6) ECIES-style file encryption using Auditor ECC public key
    auditor_pub = ECC.import_key(auditor_ecc_pub_pem)
    eph = ECC.generate(curve='P-256')
    eph_pub_pem = eph.public_key().export_key(format='PEM')
    # compute shared secret: auditor_pub.pointQ * eph.d
    shared_point = auditor_pub.pointQ * eph.d
    x = int(shared_point.x)
    shared_bytes = x.to_bytes((x.bit_length()+7)//8, byteorder='big')
    aes_key = derive_aes_key_from_shared(shared_bytes)
    ct_b64, nonce_b64, tag_b64 = aes_encrypt_gcm_bytes(plaintext.encode(), aes_key)

    # 7) SHA256 hash of plaintext (hex) and sign with client's ECC key (ECDSA)
    client_ecc = ECC.generate(curve='P-256')
    client_pub_pem = client_ecc.public_key().export_key(format='PEM')
    signer = DSS.new(client_ecc, 'fips-186-3')
    msg_hash = SHA256.new(plaintext.encode())
    signature = signer.sign(msg_hash)
    signature_b64 = base64.b64encode(signature).decode()

    # 8) Construct packet
    packet = {
        'enc_file': {
            'ciphertext_b64': ct_b64,
            'nonce_b64': nonce_b64,
            'tag_b64': tag_b64,
            'ephemeral_pub_pem': eph_pub_pem,
            'line_tags': line_tags,
            'line_refs': lines  # for demo; remove to enforce "no plaintext until decrypt"
        },
        'enc_marks': enc_marks_ints,
        'enc_marks_product': combined_ct_int,
        'hash': msg_hash.hexdigest(),
        'signature_b64': signature_b64,
        'client_pub_pem': client_pub_pem
    }

    # 9) Send packet to server (new connection)
    s2 = socket.socket()
    s2.connect((server_host, server_port))
    s2.send(json.dumps(packet).encode())
    s2.close()
    print("[Client] Packet sent to server.")

if __name__ == "__main__":
    # set input_file to your text file path (input.txt by default)
    start_client(input_file='input.txt')
