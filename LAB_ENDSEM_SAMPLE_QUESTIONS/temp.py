#RSA:
import hashlib
import json
import os
import secrets
import time
from datetime import datetime
from math import gcd

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from cryptography.hazmat.primitives import padding, hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

RSA_KEY_SIZE = 4096
CANDIDATE_IDS = [1, 2, 3]
DEADLINE = "2099-12-31 23:59:59"
ballots = []


# Small educational Paillier parameters ONLY; not secure for real elections.
PAILLIER_P = 17
PAILLIER_Q = 19
PAILLIER_N = PAILLIER_P * PAILLIER_Q
PAILLIER_N2 = PAILLIER_N * PAILLIER_N
PAILLIER_G = PAILLIER_N + 1
PAILLIER_LAMBDA = lcm(PAILLIER_P - 1, PAILLIER_Q - 1)
PAILLIER_MU = pow(PAILLIER_LAMBDA, -1, PAILLIER_N)
encrypted_totals = {cid: None for cid in CANDIDATE_IDS}
tally_ready = False

# ============================================================
# RSA KEY GENERATION
# ============================================================

def generate_rsa_keys():

    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=RSA_KEY_SIZE
    )

    public_key = private_key.public_key()

    return private_key, public_key


# ============================================================
# RSA - PROTECT AES KEY
# ============================================================

def rsa_encrypt_key(aes_key, public_key):

    return public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )


def rsa_decrypt_key(encrypted_key, private_key):

    return private_key.decrypt(
        encrypted_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

def encrypt(public_key, data):
    aes_key = bytes.fromhex(
        "0123456789ABCDEF0123456789ABCDEF"
        "0123456789ABCDEF0123456789ABCDEF"
    )

    # RSA encrypt AES key

    encrypted_aes_key = rsa_encrypt_key(
        aes_key,
        public_key
    )

    # Convert string to bytes
    data = data.encode()

    # CBC requires a 16-byte IV
    iv = os.urandom(16)

    # Create AES cipher
    cipher = AES.new(aes_key, AES.MODE_CBC, iv)

    # Pad plaintext
    padded_text = pad(data, AES.block_size)

    # Encrypt
    ciphertext = cipher.encrypt(padded_text)

    # Display ciphertext in HEX
    return encrypted_aes_key,iv,ciphertext

def decrypt(private_key, encrypted_aes_key, iv, ciphertext):
    decrypted_aes_key = rsa_decrypt_key(
        encrypted_aes_key,
        private_key
    )

    # AES decrypt file

    # Create cipher again for decryption
    cipher = AES.new(decrypted_aes_key, AES.MODE_CBC, iv)

    # Decrypt
    decrypted = cipher.decrypt(ciphertext)

    # Remove padding
    decrypted = unpad(decrypted, AES.block_size)

    # Convert bytes back to string
    return decrypted.decode()


def hash_message(message):
    return hashlib.sha512(message.encode("utf-8")).digest()


# ================= ELGAMAL =================

# ELGAMAL SIGNATURE: tiny educational parameters only
ELGAMAL_P = 467
ELGAMAL_G = 2
ELGAMAL_PRIVATE_KEY = 127
ELGAMAL_PUBLIC_KEY = pow(ELGAMAL_G, ELGAMAL_PRIVATE_KEY, ELGAMAL_P)


def elgamal_sign(message):
    h = int.from_bytes(hash_message(message), "big") % (ELGAMAL_P - 1)
    while True:
        k = secrets.randbelow(ELGAMAL_P - 2) + 1
        if gcd(k, ELGAMAL_P - 1) == 1:
            break
    r = pow(ELGAMAL_G, k, ELGAMAL_P)
    k_inverse = pow(k, -1, ELGAMAL_P - 1)
    s = (k_inverse * (h - ELGAMAL_PRIVATE_KEY * r)) % (ELGAMAL_P - 1)
    return (r, s)


def elgamal_verify(message, signature):
    r, s = signature
    if not (0 < r < ELGAMAL_P and 0 <= s < ELGAMAL_P - 1):
        return False
    h = int.from_bytes(hash_message(message), "big") % (ELGAMAL_P - 1)
    left = (
        pow(ELGAMAL_PUBLIC_KEY, r, ELGAMAL_P)
        * pow(r, s, ELGAMAL_P)
    ) % ELGAMAL_P
    right = pow(ELGAMAL_G, h, ELGAMAL_P)
    return left == right


# PAILLIER ENCRYPTION AND HOMOMORPHIC TALLY
def paillier_encrypt(message):
    if not (0 <= message < PAILLIER_N):
        raise ValueError("Paillier message must be between 0 and n-1.")
    while True:
        r = secrets.randbelow(PAILLIER_N - 1) + 1
        if gcd(r, PAILLIER_N) == 1:
            break
    return (
        pow(PAILLIER_G, message, PAILLIER_N2)
        * pow(r, PAILLIER_N, PAILLIER_N2)
    ) % PAILLIER_N2


def paillier_decrypt(ciphertext):
    u = pow(ciphertext, PAILLIER_LAMBDA, PAILLIER_N2)
    L_value = (u - 1) // PAILLIER_N
    return (L_value * PAILLIER_MU) % PAILLIER_N



def initialize_encrypted_totals():
    global encrypted_totals
    encrypted_totals = {cid: paillier_encrypt(0) for cid in CANDIDATE_IDS}


def create_indicators(candidate):
    indicators = {}
    for cid in CANDIDATE_IDS:
        value = 1 if cid == candidate else 0
        indicators[cid] = paillier_encrypt(value)
    return indicators

def update_totals(indicators):
    global tally_ready
    for cid in CANDIDATE_IDS:
        encrypted_totals[cid] = (
            encrypted_totals[cid] * indicators[cid]
        ) % PAILLIER_N2
    tally_ready = False



def show_encrypted_totals():
    print("\nEncrypted running totals:")
    for cid in CANDIDATE_IDS:
        print("Candidate", cid, ":", encrypted_totals[cid])


# INPUT AND ACCESS CHECKS
def check_deadline():
    current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    return current_time <= DEADLINE


def check_role(expected_role):
    role = input("Enter role (" + expected_role + "): ").strip()
    if role != expected_role:
        print("Access denied.")
        return False
    return True


def cast_vote(rsa_public_key):
    global tally_ready
    if not check_deadline():
        print("Voting deadline has passed!")
        return

    constituency = input("Enter constituency ID: ").strip()
    if not constituency:
        print("Constituency ID cannot be empty.")
        return

    try:
        candidate = int(input("Enter candidate ID: "))
    except ValueError:
        print("Candidate ID must be an integer.")
        return

    if candidate not in CANDIDATE_IDS:
        print("Invalid candidate ID. Valid IDs:", CANDIDATE_IDS)
        return

    ballot = {"candidate_id": candidate, "constituency_id": constituency}
    data = json.dumps(ballot, sort_keys=True)
    digest = hash_message(data)
    signature = elgamal_sign(data)
    encrypted_aes_key, iv, ciphertext = encrypt(rsa_public_key, data)
    indicators = create_indicators(candidate)
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    record = {
        "constituency": constituency,
        "timestamp": timestamp,
        "ballot": ciphertext,
        "iv": iv,
        "key": encrypted_aes_key,
        "hash": digest,
        "signature": signature,
        "indicators": indicators
    }
    ballots.append(record)
    update_totals(indicators)

    print("\nVote submitted successfully!")
    print("Encrypted ballot (hex):", ciphertext.hex())
    print("Encrypted AES key (hex):", encrypted_aes_key.hex())
    print("IV (hex):", iv.hex())
    print("SHA-512 digest (hex):", digest.hex())
    print("ElGamal signature:", signature)
    print("Timestamp:", timestamp)

    ballots.append(record)

    print("\nVote submitted successfully!")
    print("Encrypted ballot (hex):", ciphertext.hex())
    print("Encrypted AES key (hex):", encrypted_aes_key.hex())
    print("SHA-512 digest (hex):", hash_message(data))
    print("ElGamal signature:", signature)
    print("Timestamp:", timestamp)


# VERIFY BALLOTS
def verify_ballots(rsa_private_key):
    if not ballots:
        print("No ballots available.")
        return

    for i, record in enumerate(ballots, start=1):
        print("\nBallot", i)
        try:
            data = decrypt(
                rsa_private_key, record["key"], record["iv"], record["ballot"]
            )
            recomputed_digest = hash_message(data)
            hash_ok = recomputed_digest == record["hash"]
            signature_ok = elgamal_verify(data, record["signature"])
            timestamp_ok = record["timestamp"] <= DEADLINE

            print("Hash valid:", hash_ok)
            print("Signature valid:", signature_ok)
            print("Timestamp valid:", timestamp_ok)
            if hash_ok and signature_ok and timestamp_ok:
                print("Ballot contents:", data)
            else:
                print("Ballot failed one or more checks.")
        except (ValueError, KeyError, TypeError) as error:
            print("Could not verify ballot:", error)


# ENCRYPTED AGGREGATION AND FINAL DECRYPTION
def tally_votes():
    global tally_ready
    if not ballots:
        print("No votes to tally.")
        return
    show_encrypted_totals()
    tally_ready = True
    print("\nEncrypted tally is ready for authorized decryption.")


def decrypt_aggregate():
    if not tally_ready:
        print("Run the tally first!")
        return
    if input("Enter role (admin): ").strip() != "admin":
        print("Access denied.")
        return

    print("Two authorities must approve decryption.")
    approval1 = input("Authority 1 password (demo: admin1): ")
    approval2 = input("Authority 2 password (demo: admin2): ")
    if approval1 != "admin1" or approval2 != "admin2":
        print("Approval failed.")
        return

    print("\nFinal decrypted vote totals:")
    overall_total = 0
    for cid in CANDIDATE_IDS:
        count = paillier_decrypt(encrypted_totals[cid])
        print("Candidate", cid, ":", count)
        overall_total += count
    print("Overall votes:", overall_total)


# SEARCH BY PLAINTEXT METADATA
def search_ballots():
    print("1. Search by constituency")
    print("2. Search from a timestamp")
    choice = input("Choice: ").strip()

    if choice == "1":
        value = input("Enter constituency ID: ").strip()
        results = [b for b in ballots if b["constituency"] == value]
    elif choice == "2":
        value = input("Enter start time (YYYY-MM-DD HH:MM:SS): ").strip()
        try:
            datetime.strptime(value, "%Y-%m-%d %H:%M:%S")
        except ValueError:
            print("Invalid timestamp format.")
            return
        results = [b for b in ballots if b["timestamp"] >= value]
    else:
        print("Invalid choice.")
        return

    print("Matching ballots:", len(results))
    for record in results:
        print(
            "Constituency:", record["constituency"],
            "| Timestamp:", record["timestamp"]
        )

