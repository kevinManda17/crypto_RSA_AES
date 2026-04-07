"""Interactive client for the RSA/AES handshake demonstration.

This script provides a simple terminal menu allowing a user to
step through the stages of the cryptographic handshake implemented
by the accompanying server.  The client can:

* Fetch the server’s RSA public key via `/public-key` and load it
  into a cryptography object.
* Generate a fresh AES‑256 key and store it locally.
* Encrypt the AES key with the server’s public RSA key and POST
  it to `/handshake` to establish a session.  The returned
  session identifier is stored for subsequent requests.
* Encrypt arbitrary plaintext using AES‑GCM, send it to
  `/message` and decrypt the response.  A simple
  transformation (upper‑casing the message) is applied by the
  server, demonstrating a secure round trip.
* Demonstrate error handling by attempting to send a message
  without establishing a session.

The server URL defaults to `http://rsa-server:5000` when run inside
Docker, but can be overridden by setting the `SERVER_URL` environment
variable.  When running the client directly on your host, set
SERVER_URL to `http://localhost:5000` or the appropriate IP
address.
"""

import base64
import os
import sys
from typing import Optional

import requests
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


# Resolve the server URL from the environment or fall back to a
# sensible default.  When running within Docker Compose this will be
# `http://rsa-server:5000`.  When running locally set SERVER_URL
# accordingly (e.g. `export SERVER_URL=http://localhost:5000`).
SERVER_URL = os.environ.get('SERVER_URL', 'http://rsa-server:5000')

public_key = None  # type: Optional[object]
aes_key: Optional[bytes] = None
session_id: Optional[str] = None


def fetch_public_key() -> None:
    """Retrieve and load the server's RSA public key."""
    global public_key
    try:
        resp = requests.get(f"{SERVER_URL}/public-key", timeout=10)
        resp.raise_for_status()
    except Exception as exc:
        print(f"Error fetching public key: {exc}")
        return
    data = resp.json()
    key_pem = data.get('key')
    if not key_pem:
        print("Server response did not contain a key")
        return
    try:
        public_key = serialization.load_pem_public_key(key_pem.encode('utf-8'))
        print(f"Loaded RSA public key (size {data.get('size')} bits)")
    except Exception as exc:
        print(f"Error loading public key: {exc}")


def generate_aes_key() -> None:
    """Generate a random 256‑bit AES key and store it."""
    global aes_key
    aes_key = os.urandom(32)
    print("Generated new AES‑256 key: {}".format(base64.b64encode(aes_key).decode('utf-8')))


def perform_handshake() -> None:
    """Encrypt the AES key with the server's public key and start a session."""
    global session_id
    if public_key is None:
        print("You must fetch the server's public key first.")
        return
    if aes_key is None:
        print("You must generate an AES key first.")
        return
    try:
        encrypted_key = public_key.encrypt(
            aes_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )
        payload = {"key": base64.b64encode(encrypted_key).decode('utf-8')}
        resp = requests.post(f"{SERVER_URL}/handshake", json=payload, timeout=10)
        resp.raise_for_status()
        data = resp.json()
        session_id = data.get('session_id')
        expires_at = data.get('expires_at')
        if session_id:
            print(f"Handshake successful. Session ID: {session_id}")
            print(f"Session expires at: {expires_at}")
        else:
            print(f"Unexpected response: {data}")
    except Exception as exc:
        print(f"Handshake failed: {exc}")


def send_message() -> None:
    """Prompt for a message, encrypt it, send it and decrypt the response."""
    if session_id is None or aes_key is None:
        print("You must perform the handshake first.")
        return
    plaintext = input("Enter message to send: ").strip()
    if not plaintext:
        print("Empty message.")
        return
    try:
        aesgcm = AESGCM(aes_key)
        nonce = os.urandom(12)
        ct_and_tag = aesgcm.encrypt(nonce, plaintext.encode('utf-8'), None)
        ciphertext, tag = ct_and_tag[:-16], ct_and_tag[-16:]
        payload = {
            "ciphertext": base64.b64encode(ciphertext).decode('utf-8'),
            "nonce": base64.b64encode(nonce).decode('utf-8'),
            "tag": base64.b64encode(tag).decode('utf-8'),
        }
        headers = {"X-Session-ID": session_id}
        resp = requests.post(f"{SERVER_URL}/message", json=payload, headers=headers, timeout=10)
        if resp.status_code >= 400:
            print(f"Server returned error {resp.status_code}: {resp.text}")
            return
        data = resp.json()
        # decode response and decrypt
        resp_ct = base64.b64decode(data['ciphertext'])
        resp_nonce = base64.b64decode(data['nonce'])
        resp_tag = base64.b64decode(data['tag'])
        decrypted = aesgcm.decrypt(resp_nonce, resp_ct + resp_tag, None)
        print("Response from server: {}".format(decrypted.decode('utf-8')))
    except Exception as exc:
        print(f"Error sending message: {exc}")


def demo_invalid_session() -> None:
    """Attempt to send a message without a valid session to illustrate errors."""
    print("Sending message without a valid session …")
    try:
        aes_local = os.urandom(32)
        aesgcm = AESGCM(aes_local)
        nonce = os.urandom(12)
        ct_and_tag = aesgcm.encrypt(nonce, b"hello", None)
        ct, tag = ct_and_tag[:-16], ct_and_tag[-16:]
        payload = {
            "ciphertext": base64.b64encode(ct).decode('utf-8'),
            "nonce": base64.b64encode(nonce).decode('utf-8'),
            "tag": base64.b64encode(tag).decode('utf-8'),
        }
        headers = {"X-Session-ID": "invalid-session"}
        resp = requests.post(f"{SERVER_URL}/message", json=payload, headers=headers, timeout=10)
        print(f"Response status: {resp.status_code}, body: {resp.text}")
    except Exception as exc:
        print(f"Error: {exc}")


def auto_demo() -> None:
    """Perform all steps automatically with a sample message."""
    print("Running automatic demo …")
    fetch_public_key()
    generate_aes_key()
    perform_handshake()
    if session_id:
        # send a sample message
        global aes_key  # ensure AES key is visible inside send_message
        plaintext = "Hello secure world"
        try:
            aesgcm = AESGCM(aes_key)
            nonce = os.urandom(12)
            ct_and_tag = aesgcm.encrypt(nonce, plaintext.encode('utf-8'), None)
            ct, tag = ct_and_tag[:-16], ct_and_tag[-16:]
            payload = {
                "ciphertext": base64.b64encode(ct).decode('utf-8'),
                "nonce": base64.b64encode(nonce).decode('utf-8'),
                "tag": base64.b64encode(tag).decode('utf-8'),
            }
            headers = {"X-Session-ID": session_id}
            resp = requests.post(f"{SERVER_URL}/message", json=payload, headers=headers, timeout=10)
            if resp.status_code >= 400:
                print(f"Server returned error {resp.status_code}: {resp.text}")
                return
            data = resp.json()
            resp_ct = base64.b64decode(data['ciphertext'])
            resp_nonce = base64.b64decode(data['nonce'])
            resp_tag = base64.b64decode(data['tag'])
            reply = aesgcm.decrypt(resp_nonce, resp_ct + resp_tag, None).decode('utf-8')
            print(f"Server replied: {reply}")
        except Exception as exc:
            print(f"Demo failed: {exc}")


def print_menu() -> None:
    """Display the available options to the user."""
    print("\n=== RSA/AES Handshake Demo ===")
    print("Server URL:", SERVER_URL)
    print("1) Fetch server public key")
    print("2) Generate AES key")
    print("3) Perform handshake")
    print("4) Send message")
    print("5) Send message without valid session (demo error)")
    print("6) Automatic demo")
    print("0) Quit")


def main() -> None:
    while True:
        print_menu()
        try:
            choice = input("Select an option: ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\nExiting.")
            break
        if choice == '1':
            fetch_public_key()
        elif choice == '2':
            generate_aes_key()
        elif choice == '3':
            perform_handshake()
        elif choice == '4':
            send_message()
        elif choice == '5':
            demo_invalid_session()
        elif choice == '6':
            auto_demo()
        elif choice == '0':
            print("Goodbye!")
            break
        else:
            print("Invalid choice, please select a valid option.")


if __name__ == '__main__':
    main()