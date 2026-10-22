# secure_message.py
# One-file educational demo: TCP socket + AES + RSA + SHA-512 + ElGamal signature.
# Start once as server ("s"), then again as client ("c").

import socket
import json
import os
import hashlib
import secrets
from math import gcd

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization


HOST = "127.0.0.1"
PORT = 5000

#rsa key generation:
rsa_private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
rsa_public = rsa_private.public_key()


#elgamal:
P,G,X = 467, 2, 127
Y = pow(G,X,P)

def sha512(message):
    return hashlib.sha512(message.encode()).hexdigest()

def encrypt_message(message, server_public_key):
    aes_key = os.urandom(32)
    iv = os.urandom(16)
    cipher = AES.new(aes_key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(message.encode(), AES.block_size))

    encrypted_key = server_public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    return encrypted_key, iv, ciphertext


def decrypt_message(encrypted_key, iv, ciphertext):
    aes_key = rsa_private.decrypt(
        encrypted_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    cipher = AES.new(aes_key, AES.MODE_CBC, iv)

    return unpad(cipher.decrypt(ciphertext), AES.block_size).decode()

def sign(message):
    h = int(sha512(message), 16) % (P - 1)
    while True:
        k = secrets.randbelow(P - 2) + 1
        if gcd(k, P - 1) == 1:
            break
    r = pow(G, k, P)
    s = (pow(k, -1, P - 1) * (h - X * r)) % (P - 1)
    return [r, s]

def verify(message, signature):
    r, s = signature
    if not (0 < r < P and 0 <= s < P - 1):
        return False
    h = int(sha512(message), 16) % (P - 1)
    left = (pow(Y, r, P) * pow(r, s, P)) % P
    right = pow(G, h, P)
    return left == right

def send_json(sock, data):
    sock.sendall(json.dumps(data).encode() + b"\n")


def receive_json(sock):
    data = b""
    while not data.endswith(b"\n"):
        part = sock.recv(4096)
        if not part:
            raise ConnectionError("Connection closed.")
        data += part
    return json.loads(data.decode().strip())

def server():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((HOST, PORT))
        s.listen(1)
        print("Server waiting for a client...")
        conn, address = s.accept()

        with conn:

            print("Connected: ", address)

            #send server's public rsa key to client
            public_pem = rsa_public.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ).decode()
            send_json(conn, {"public_key": public_pem})

            request = receive_json(conn)

            message = decrypt_message(
                bytes.fromhex(request["encrypted_key"]),
                bytes.fromhex(request["iv"]),
                bytes.fromhex(request["ciphertext"])
            )

            hash_ok = sha512(message) == request["hash"]
            signature_ok = verify(message, request["signature"])

            response = {
                "message_received": message,
                "hash_valid": hash_ok,
                "signature_valid": signature_ok
            }

            send_json(conn, response)
            print("Hash valid:", hash_ok)
            print("Signature valid:", signature_ok)
def client():
    message = input("Enter message: ")

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((HOST, PORT))

        # Receive server's public RSA key
        key_message = receive_json(s)

        server_public_key = serialization.load_pem_public_key(
            key_message["public_key"].encode()
        )

        # Encrypt message
        encrypted_key, iv, ciphertext = encrypt_message(
            message, server_public_key
        )

        # Send encrypted data, hash and signature
        request = {
            "encrypted_key": encrypted_key.hex(),
            "iv": iv.hex(),
            "ciphertext": ciphertext.hex(),
            "hash": sha512(message),
            "signature": sign(message)
        }

        send_json(s, request)

        # Receive verification results
        response = receive_json(s)

    print("\nServer response:")
    print("Message received:", response["message_received"])
    print("Hash valid:", response["hash_valid"])
    print("Signature valid:", response["signature_valid"])

mode = input("Run as server or client? (s/c): ").strip().lower()
if mode == "s":
    server()
elif mode == "c":
    client()
else:
    print("Enter s or c.")