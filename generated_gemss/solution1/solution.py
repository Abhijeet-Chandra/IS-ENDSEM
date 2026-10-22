from Crypto.Cipher import AES, DES, DES3, PKCS1_OAEP
from Crypto.Util.Padding import pad, unpad
from Crypto.PublicKey import RSA, ECC
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes
from pathlib import Path
from math import gcd
import random
import secrets
import hashlib
import hmac
import math
import base64
import json
import re

# Standalone educational lab; local teaching keys are stored in keys/.
TITLE = 'SecureX'
ASYMMETRIC = 'DH'
BASE = Path(__file__).resolve().parent
BLOCK_CIPHER, KEY_BYTES = AES, 32
P, G = 467, 2
SIG_P, SIG_G = 467, 2


# =========================================================
# SSE - CREATE ENCRYPTED INDEX AND SEARCH
# =========================================================

def token(key, word):
    return hmac.new(key, word.lower().encode(), hashlib.sha256).hexdigest()


def create_index(documents, key, iv=None):
    index = {}
    for doc_id, doc in documents.items():
        for word in set(doc.lower().split()):
            record_iv = get_random_bytes(BLOCK_CIPHER.block_size)
            enc_id = symmetric_encrypt(doc_id, key, record_iv)
            index.setdefault(token(SEARCH_KEY, word), []).append((record_iv.hex(), enc_id))
    (BASE / "index.json").write_text(json.dumps(index), encoding="utf-8")
    return index


def search(index, query, key, documents=None):
    results = []
    for iv_hex, enc_id in index.get(token(SEARCH_KEY, query.strip()), []):
        doc_id = symmetric_decrypt(enc_id, key, bytes.fromhex(iv_hex))
        results.append((doc_id, read_document(doc_id)))
    return results


# =========================================================
# HOMOMORPHIC ENCRYPTION AND DECRYPTION
# =========================================================

def encrypt_homomorphic_RSA(m):
    p = 11
    q = 13
    n = p * q
    phi = (p - 1) * (q - 1)
    e = 7
    while gcd(e, phi) != 1:
        e += 1
    d = pow(e, -1, phi)
    # print("Public key:", (e, n))
    # print("Private key:", (d, n))
    return pow(m, e, n),n

def decrypt_homomorphic_RSA(c):
    p = 11
    q = 13
    n = p * q
    phi = (p - 1) * (q - 1)
    e = 7
    while gcd(e, phi) != 1:
        e += 1
    d = pow(e, -1, phi)
    return pow(c, d, n)

def expected_homomorphic(a, b):
    return (a * b) % 143


def calculate_homomorphic(a, b):
    if not (0 <= a < 143 and 0 <= b < 143):
        raise ValueError("Use integers from 0 to 142")
    c1, modulus = encrypt_homomorphic_RSA(a)
    c2, modulus = encrypt_homomorphic_RSA(b)
    return {"operation": "multiplication modulo 143", "ciphertext": c1 * c2 % modulus}


def decrypt_homomorphic(ciphertext):
    return decrypt_homomorphic_RSA(ciphertext)


# =========================================================
# GENERATE KEYS, SIGN MESSAGE AND VERIFY SIGNATURE
# =========================================================

def digest_text(text):
    return hashlib.sha1(text.encode()).hexdigest()

def generate_keys():
    private_key = secrets.randbelow(SIG_P - 2) + 1
    return private_key, pow(SIG_G, private_key, SIG_P)


def sign_message(content, private_key):
    value = int.from_bytes(hashlib.sha256(content.encode()).digest(), "big")
    k = secrets.randbelow(SIG_P - 2) + 1
    while math.gcd(k, SIG_P - 1) != 1:
        k = secrets.randbelow(SIG_P - 2) + 1
    r = pow(SIG_G, k, SIG_P)
    s = ((value - private_key * r) * pow(k, -1, SIG_P - 1)) % (SIG_P - 1)
    return [r, s], digest_text(content)

def verify_signature(content, signature, public_key):
    r, s = signature
    if not (0 < r < SIG_P and 0 <= s < SIG_P - 1):
        return False
    value = int.from_bytes(hashlib.sha256(content.encode()).digest(), "big")
    y = public_key
    return pow(SIG_G, value, SIG_P) == pow(y, r, SIG_P) * pow(r, s, SIG_P) % SIG_P


# =========================================================
# AES-256 ENCRYPTION AND DECRYPTION
# =========================================================

def symmetric_encrypt(plaintext, key, iv):
    cipher = BLOCK_CIPHER.new(key, BLOCK_CIPHER.MODE_CBC, iv=iv)
    return cipher.encrypt(pad(plaintext.encode(), BLOCK_CIPHER.block_size)).hex()


def symmetric_decrypt(ciphertext_hex, key, iv):
    cipher = BLOCK_CIPHER.new(key, BLOCK_CIPHER.MODE_CBC, iv=iv)
    return unpad(cipher.decrypt(bytes.fromhex(ciphertext_hex)), BLOCK_CIPHER.block_size).decode()


# =========================================================
# DH KEY PROTECTION
# =========================================================

def b64(data):
    return base64.b64encode(data).decode("ascii")

def unb64(data):
    return base64.b64decode(data)

def wrap_key(key):
    ephemeral = secrets.randbelow(P - 3) + 2
    public = pow(G, ephemeral, P)
    shared = pow(PUBLIC_Y, ephemeral, P)
    shared_key = hashlib.sha256(str(shared).encode()).digest()
    cipher = AES.new(shared_key, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(key)
    return [public, b64(cipher.nonce), b64(ciphertext), b64(tag)]

def unwrap_key(wrapped):
    public, nonce, ciphertext, tag = wrapped
    shared = pow(public, PRIVATE_X, P)
    shared_key = hashlib.sha256(str(shared).encode()).digest()
    cipher = AES.new(shared_key, AES.MODE_EAX, nonce=unb64(nonce))
    return cipher.decrypt_and_verify(unb64(ciphertext), unb64(tag))


# =========================================================
# Additive CLASSICAL CIPHER
# =========================================================

def additive_encrypt(plaintext, key):
    result = []
    for ch in plaintext:
        if ch in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz":
            base = ord('A') if ch.isupper() else ord('a')
            result.append(chr((ord(ch) - base + key) % 26 + base))
        else:
            result.append(ch)
    return "".join(result)

def additive_decrypt(ciphertext, key):
    return additive_encrypt(ciphertext, -key)

def classical_demo(text):
    if any(ch.isalpha() and ch not in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz" for ch in text):
        raise ValueError("Lab 1 uses English A-Z letters")
    encrypted = additive_encrypt(text, 20)
    decrypted = additive_decrypt(encrypted, 20)
    return {"algorithm": "Additive", "ciphertext": encrypted, "decrypted_text": decrypted}


# =========================================================
# FILE STORAGE
# =========================================================

def initialize():
    global SERVER_RSA, SERVER_ECC, PRIVATE_X, PUBLIC_Y
    for name in ("encrypted", "hashes", "signature", "public_key", "add", "metadata", "keys"):
        (BASE / name).mkdir(parents=True, exist_ok=True)
    key_file = BASE / "keys" / "local.json"
    if key_file.exists():
        state = json.loads(key_file.read_text())
    else:
        state = {"symmetric": get_random_bytes(KEY_BYTES).hex(),
                 "search": get_random_bytes(32).hex()}
        if ASYMMETRIC == "RSA":
            state["private"] = RSA.generate(2048).export_key().decode()
        elif ASYMMETRIC == "ECDH":
            state["private"] = ECC.generate(curve="P-256").export_key(format="PEM")
        else:
            state["private"] = secrets.randbelow(P - 3) + 2
        key_file.write_text(json.dumps(state), encoding="utf-8")
    if ASYMMETRIC == "RSA":
        SERVER_RSA = RSA.import_key(state["private"])
    elif ASYMMETRIC == "ECDH":
        SERVER_ECC = ECC.import_key(state["private"])
    else:
        PRIVATE_X = state["private"]
        PUBLIC_Y = pow(G, PRIVATE_X, P)
    return bytes.fromhex(state["symmetric"]), bytes.fromhex(state["search"])


def record_path(folder, filename):
    if (not filename or filename in (".", "..") or
            any(ch in filename for ch in '<>:"/\\|?*') or
            filename.endswith((".", " ")) or
            filename.split('.')[0].upper() in
            {"CON", "PRN", "AUX", "NUL", *[f"COM{i}" for i in range(1, 10)],
             *[f"LPT{i}" for i in range(1, 10)]}):
        raise ValueError("Enter a plain filename, for example report1.txt")
    return BASE / folder / filename


def write_file(folder, filename, value):
    record_path(folder, filename).write_text(value, encoding="utf-8")


def read_file(folder, filename):
    return record_path(folder, filename).read_text(encoding="utf-8")


def load_documents():
    documents = {}
    for file in (BASE / "encrypted").iterdir():
        if file.is_file():
            try:
                documents[file.name] = read_document(file.name)
            except (ValueError, OSError, KeyError, TypeError):
                print("Skipping invalid document:", file.name)
    return documents


# =========================================================
# STUDENT
# =========================================================

def student(filename, plaintext, num1, num2, key, iv):
    if record_path("encrypted", filename).exists():
        raise ValueError("Document already exists!")
    homomorphic = calculate_homomorphic(num1, num2)
    # A fresh IV is stored for each record.
    iv = get_random_bytes(BLOCK_CIPHER.block_size)
    ciphertext = symmetric_encrypt(plaintext, key, iv)
    private_key, public_key = generate_keys()
    signature, hash_value = sign_message(ciphertext, private_key)
    metadata = {"iv": iv.hex(), "wrapped_key": wrap_key(key), "num1": num1, "num2": num2}
    write_file("encrypted", filename, ciphertext)
    write_file("hashes", filename, hash_value)
    write_file("signature", filename, json.dumps(signature))
    write_file("public_key", filename, json.dumps(public_key))
    write_file("add", filename, json.dumps(homomorphic))
    write_file("metadata", filename, json.dumps(metadata))
    print("Encrypted", homomorphic["operation"], ":", homomorphic["ciphertext"])
    print("Record uploaded successfully.")


# =========================================================
# READ DOCUMENT
# =========================================================

def read_document(filename):
    ciphertext = read_file("encrypted", filename)
    if not verify_saved_hash(ciphertext, read_file("hashes", filename)):
        raise ValueError("Integrity verification failed.")
    signature = json.loads(read_file("signature", filename))
    public_key = json.loads(read_file("public_key", filename))
    if not verify_signature(ciphertext, signature, public_key):
        raise ValueError("Digital signature verification failed.")
    metadata = json.loads(read_file("metadata", filename))
    key = unwrap_key(metadata["wrapped_key"])
    return symmetric_decrypt(ciphertext, key, bytes.fromhex(metadata["iv"]))


# =========================================================
# FACULTY
# =========================================================

def faculty(filename, num1=None, num2=None, key=None, iv=None):
    ciphertext = read_file("encrypted", filename)
    plaintext = read_document(filename)
    print("Hash verified successfully.")
    print("Signature verified:", True)
    metadata = json.loads(read_file("metadata", filename))
    homomorphic = json.loads(read_file("add", filename))
    result = decrypt_homomorphic(homomorphic["ciphertext"])
    expected = expected_homomorphic(metadata["num1"], metadata["num2"])
    print("Homomorphic decrypted result:", result)
    if result != expected:
        raise ValueError("Homomorphic verification failed.")
    print("homomorphic verified")
    print("\nPlaintext:")
    print(plaintext)
    return plaintext


# =========================================================
# HOD
# =========================================================

def hod(filename):
    ciphertext = read_file("encrypted", filename)
    saved_hash = read_file("hashes", filename)
    signature = json.loads(read_file("signature", filename))
    public_key = json.loads(read_file("public_key", filename))
    result = (verify_saved_hash(ciphertext, saved_hash) and
              verify_signature(ciphertext, signature, public_key))
    print("Signature and hash verified:", result)
    return result


# =========================================================
# MAIN MENU
# =========================================================

def main():
    global SEARCH_KEY
    key, SEARCH_KEY = initialize()
    documents = load_documents()
    num1=0
    num2=0
    iv = None
    create_index(documents, key)
    while True:

        print("\n" + "=" * 40)
        print("             " + TITLE)
        print("=" * 40)
        print("1. Student")
        print("2. Faculty")
        print("3. HoD")
        print("4. Exit")
        print("=" * 40)

        choice = input("Enter choice: ")

        if choice == "1":

            while True:
                print("\n------ Student Menu ------")
                print("1. Add a new document")
                print("2. view documents")
                print("3. Back to main menu")
                print("4. Classical cipher demonstration")

                student_choice = input("Enter choice: ")

                if student_choice == "1":

                    filename = input("Enter filename: ").strip()

                    if filename == "":
                        print("Filename cannot be empty.")
                        continue

                    if filename in documents:
                        print("Document already exists!")
                        continue

                    plaintext = input("Enter document record: ")


                    try:
                        num1 = int(input("Enter first integer: "))
                        num2 = int(input("Enter second integer: "))
                    except ValueError:
                        print("Enter valid integers.")
                        continue

                    try:
                        student(filename, plaintext, num1, num2, key, iv)
                        documents[filename] = plaintext
                        create_index(documents, key)
                    except (ValueError, OSError) as exc:
                        print(exc)

                elif student_choice == "2":

                    if not documents:
                        print("No documents uploaded yet.")
                    else:
                        print("\n------ All Documents ------")

                        for filename, plaintext in documents.items():
                            print(f"\nFilename: {filename}")
                            print(f"Plaintext: {plaintext}")
                elif student_choice == "4":
                    try:
                        result = classical_demo(input("Enter classical cipher text: "))
                        print("Ciphertext:", result["ciphertext"])
                        print("Decrypted text:", result["decrypted_text"])
                    except ValueError as exc:
                        print(exc)

                elif student_choice == "3":
                    break

                else:
                    print("Invalid choice. Please try again.")

        elif choice == "2":

            while True:
                print("\n------ Faculty Menu ------")
                print("1. Verify and decrypt a document")
                print("2. Enter searchable text")
                print("3. Back to main menu")

                faculty_choice = input("Enter choice: ")

                if faculty_choice == "1":

                    filename = input("Enter filename: ").strip()

                    if filename not in documents:
                        print("Document not found!")
                        continue


                    try:
                        faculty(filename)
                    except (ValueError, OSError, KeyError, TypeError) as exc:
                        print(exc)

                elif faculty_choice == "2":

                    if not documents:
                        print("No documents uploaded yet.")
                    else:                        
                        search_text = input("Enter searchable text: ").lower()
                        encrypted_index = json.loads((BASE / "index.json").read_text())
                        try:
                            results = search(encrypted_index, search_text, key, documents)
                        except (ValueError, OSError, KeyError, TypeError) as exc:
                            print(exc)
                            continue
                        
                        
                        if results:
                            for doc_id, doc in results:
                                print(doc_id, ":", doc)
                        else:
                            print("No matching documents found")
                        

                elif faculty_choice == "3":
                    break

                else:
                    print("Invalid choice. Please try again.")

        elif choice == "3":

            filename = input("Enter filename: ")

            try:
                hod(filename)
            except (ValueError, OSError, KeyError, TypeError) as exc:
                print(exc)

        elif choice == "4":

            print("\nExiting " + TITLE + "...")
            break

        else:

            print("\nInvalid choice. Please try again.")


# =========================================================
# CRYPTO EVENT TIMESTAMPS AND TIMINGS
# =========================================================

from datetime import datetime
from time import perf_counter_ns
from functools import wraps

EVENT_FILENAME = None
EVENT_ENTITY = None
ACTION_EVENTS = None


def crypto_event(operation, started_at, elapsed_ms, status, details):
    event = {"started_at": started_at,
             "timestamp": datetime.now().astimezone().isoformat(timespec="milliseconds"),
             "operation": operation, "filename": EVENT_FILENAME, "entity": EVENT_ENTITY,
             "duration_ms": elapsed_ms, "status": status, **details}
    BASE.mkdir(parents=True, exist_ok=True)
    with (BASE / "crypto_events.jsonl").open("a", encoding="utf-8") as stream:
        stream.write(json.dumps(event, ensure_ascii=False) + "\n")
    if ACTION_EVENTS is not None:
        ACTION_EVENTS.append(event)


def trace_crypto(function, operation, describe=None):
    @wraps(function)
    def traced(*args, **kwargs):
        started_at = datetime.now().astimezone().isoformat(timespec="milliseconds")
        start = perf_counter_ns()
        try:
            result = function(*args, **kwargs)
        except Exception as exc:
            crypto_event(operation, started_at, (perf_counter_ns() - start) / 1_000_000,
                         "error", {"error_type": type(exc).__name__})
            raise
        duration = (perf_counter_ns() - start) / 1_000_000
        details = describe(args, kwargs, result) if describe else {}
        crypto_event(operation, started_at, duration,
                     "failed" if result is False else "success", details)
        return result
    return traced


def document_context(function):
    @wraps(function)
    def contextual(*args, **kwargs):
        global EVENT_FILENAME
        previous = EVENT_FILENAME
        EVENT_FILENAME = args[0] if args else kwargs.get("filename")
        try:
            return function(*args, **kwargs)
        finally:
            EVENT_FILENAME = previous
    return contextual


def verify_saved_hash(ciphertext, saved_hash):
    computed_hash = digest_text(ciphertext)
    return hmac.compare_digest(computed_hash, saved_hash)


def signature_details(args, kwargs, result):
    message = args[0] if args else kwargs.get("message", kwargs.get("content"))
    signature = result[0]
    return {"signature": signature, "integrity_hash": result[1],
            "message_sha256": hashlib.sha256(message.encode()).hexdigest()}


def verification_details(args, kwargs, result):
    message = args[0] if args else kwargs.get("message", kwargs.get("content"))
    signature = args[1] if len(args) > 1 else kwargs["signature"]
    public_key = args[2] if len(args) > 2 else kwargs["public_key"]
    digest = hashlib.sha256(message.encode()).hexdigest()
    details = {"signature": signature, "message_sha256": digest, "verified": result}
    try:
        if isinstance(public_key, str):
            # RSA PKCS#1 v1.5 compares the complete encoded digest block.
            key = RSA.import_key(public_key)
            width = (key.n.bit_length() + 7) // 8
            digest_info = bytes.fromhex("3031300d060960864801650304020105000420" + digest)
            expected = b"\x00\x01" + b"\xff" * (width - len(digest_info) - 3) + b"\x00" + digest_info
            recovered = pow(int.from_bytes(bytes.fromhex(signature), "big"), key.e, key.n).to_bytes(width, "big")
            details.update(comparison="RSA encoded digest blocks", expected_value=expected.hex(),
                           checked_value=recovered.hex())
        elif "SIG_Q" in globals():
            # Schnorr checks the stored challenge against a recomputed challenge.
            challenge_value, response = signature
            commitment = pow(SIG_G, response, SIG_P) * pow(pow(public_key, challenge_value, SIG_P), -1, SIG_P) % SIG_P
            recomputed = int.from_bytes(hashlib.sha256(json.dumps(
                [message, commitment], ensure_ascii=False).encode()).digest(), "big") % SIG_Q
            details.update(comparison="Schnorr challenge values", expected_value=challenge_value,
                           checked_value=recomputed)
        else:
            # ElGamal checks g^H(message) = y^r * r^s (mod p).
            r, response = signature
            expected = pow(SIG_G, int(digest, 16), SIG_P)
            checked = pow(public_key, r, SIG_P) * pow(r, response, SIG_P) % SIG_P
            details.update(comparison="ElGamal verification equation", expected_value=expected,
                           checked_value=checked)
    except (ValueError, TypeError, OverflowError):
        details["comparison"] = "Invalid signature encoding or public key"
    return details


def hash_check_details(args, kwargs, result):
    ciphertext = args[0] if args else kwargs["ciphertext"]
    saved_hash = args[1] if len(args) > 1 else kwargs["saved_hash"]
    # Use the undecorated hash function to avoid reporting a second hash event.
    return {"stored_hash": saved_hash, "computed_hash": digest_text.__wrapped__(ciphertext),
            "verified": result}


# Instrument only crypto operations. Menus, prompts and ordinary messages keep
# their original output. File payload formats remain unchanged.
digest_text = trace_crypto(digest_text, "hashing", lambda a, k, r: {"hash": r})
sign_message = trace_crypto(sign_message, "signing", signature_details)
verify_signature = trace_crypto(verify_signature, "signature_verification", verification_details)
verify_saved_hash = trace_crypto(verify_saved_hash, "hash_verification", hash_check_details)
token = trace_crypto(token, "search_token_hashing", lambda a, k, r: {"hash": r})
for _function_name, _operation in (
    ("symmetric_encrypt", "encryption"), ("symmetric_decrypt", "decryption"),
    ("wrap_key", "key_encryption"), ("unwrap_key", "key_decryption"),
    ("generate_keys", "signature_key_generation"),
    ("calculate_homomorphic", "homomorphic_combination"),
    ("decrypt_homomorphic", "homomorphic_decryption"),
    ("encrypt_homomorphic_paillier", "homomorphic_encryption"),
    ("encrypt_homomorphic_RSA", "homomorphic_encryption"),
    ("encrypt_homomorphic_elgamal", "homomorphic_encryption"),
    ("create_index", "search_index_creation"), ("search", "encrypted_search"),
    ("pkse_keys", "search_key_setup"),
):
    if _function_name in globals():
        globals()[_function_name] = trace_crypto(globals()[_function_name], _operation)
# Classical helpers keep their selected algorithm and original behavior.
for _function_name in list(globals()):
    if (_function_name.endswith("_encrypt") or _function_name.endswith("_decrypt")) and not _function_name.startswith("symmetric_"):
        _function = globals()[_function_name]
        if callable(_function):
            globals()[_function_name] = trace_crypto(_function, "classical_" + _function_name)
if "challenge" in globals():
    challenge = trace_crypto(challenge, "signature_challenge_hashing",
        lambda a, k, r: {"hash": hashlib.sha256(json.dumps(
            [a[0] if a else k["content"], a[1] if len(a) > 1 else k["commitment"]],
            ensure_ascii=False).encode()).hexdigest(), "challenge": r})
for _function_name in ("student", "faculty", "hod", "read_document"):
    globals()[_function_name] = document_context(globals()[_function_name])


def display_action_summary(entity, action, events, status):
    if not events:
        return
    now = datetime.now().astimezone().isoformat(timespec="milliseconds")
    print(f"\n[{now}] {entity} - {action} ({status})")
    documents = {}
    for event in events:
        filename = event.get("filename")
        if filename is None:
            continue
        details = documents.setdefault(filename, {})
        if event.get("operation") == "hashing":
            details["hash"] = event.get("hash")
        if "integrity_hash" in event:
            details["hash"] = event["integrity_hash"]
        if "signature" in event:
            details["signature"] = event["signature"]
        if event.get("operation") == "hash_verification":
            details["hash"] = event["stored_hash"]
            details["computed_hash"] = event["computed_hash"]
            details["hash_verified"] = event["verified"]
        if event.get("operation") == "signature_verification":
            details["signature_check"] = {key: event[key] for key in
                ("comparison", "expected_value", "checked_value", "verified") if key in event}
    for filename, details in documents.items():
        # Show each stored artifact once, including when verification stops early.
        if "hash" not in details:
            try:
                details["hash"] = read_file("hashes", filename)
            except (OSError, ValueError):
                pass
        if "signature" not in details:
            try:
                details["signature"] = json.loads(read_file("signature", filename))
            except (OSError, ValueError):
                pass
        print("Document:", filename)
        if "computed_hash" in details:
            print("Stored hash:  ", details["hash"])
            print("Computed hash:", details["computed_hash"])
            print("Hash comparison:", "MATCH" if details["hash_verified"] else "MISMATCH")
        elif "hash" in details:
            print("Hash:", details["hash"])
        if "signature" in details:
            print("Signature:", details["signature"])
        if "signature_check" in details:
            check = details["signature_check"]
            print("Signature check:", check.get("comparison", "Public-key verification"))
            if "expected_value" in check:
                print("Expected verification value:", check["expected_value"])
                print("Actual verification value:  ", check["checked_value"])
            print("Signature comparison:", "MATCH" if check["verified"] else "MISMATCH")
    # Aggregate repeated operations instead of printing every internal invocation.
    timings = {}
    hidden = {"search_token_hashing", "search_key_setup", "signature_challenge_hashing"}
    for event in events:
        operation = event["operation"]
        if operation not in hidden:
            timings[operation] = timings.get(operation, 0.0) + event["duration_ms"]
    print("Times (ms): " + " | ".join(
        name.replace("_", " ") + f"={duration:.6f}" for name, duration in timings.items()))
    with (BASE / "crypto_events.jsonl").open("a", encoding="utf-8") as stream:
        stream.write(json.dumps({"timestamp": now, "operation": "action_summary",
            "entity": entity, "action": action, "status": status,
            "documents": documents, "timings_ms": timings}, ensure_ascii=False) + "\n")


def action_context(function, entity, action):
    @wraps(function)
    def contextual(*args, **kwargs):
        global ACTION_EVENTS, EVENT_ENTITY
        # Nested document verification contributes to the enclosing action only.
        if ACTION_EVENTS is not None:
            return function(*args, **kwargs)
        previous_events, previous_entity = ACTION_EVENTS, EVENT_ENTITY
        ACTION_EVENTS, EVENT_ENTITY = [], entity
        status = "success"
        try:
            result = function(*args, **kwargs)
            if result is False:
                status = "failed"
            return result
        except Exception:
            status = "error"
            raise
        finally:
            captured = ACTION_EVENTS
            ACTION_EVENTS, EVENT_ENTITY = previous_events, previous_entity
            if any(e["status"] in ("error", "failed") for e in captured):
                status = "failed" if status == "success" else status
            display_action_summary(entity, action, captured, status)
    return contextual

student = action_context(student, "Student", "Upload")
faculty = action_context(faculty, "Faculty", "Verify and decrypt")
hod = action_context(hod, "HoD", "Verify")
search = action_context(search, "Faculty", "Search")
classical_demo = action_context(classical_demo, "Student", "Classical cipher demonstration")


# =========================================================
# PROGRAM START
# =========================================================

if __name__ == "__main__":
    main()
