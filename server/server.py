"""Flask application implementing a simple RSA/AES handshake.

This server exposes three endpoints:

* `GET /public-key` – returns the RSA public key in PEM format and
  metadata.  Clients must fetch this to encrypt their AES key.
* `POST /handshake` – accepts a JSON object with an RSA‑encrypted
  AES‑256 key (base64 encoded).  The server decrypts the key,
  creates a new session identifier and stores the symmetric key
  together with a one hour expiry.  The response contains the
  session identifier and the expiry timestamp.
* `POST /message` – accepts a JSON body containing an AES‑GCM
  encrypted message: base64 encoded ciphertext, nonce and tag.
  The `X-Session-ID` header must be set to a valid session
  identifier.  If the session is valid, the payload is
  decrypted, processed and a response is encrypted using the same
  symmetric key.  The response contains new base64 encoded
  ciphertext, nonce and tag.

There is also a `GET /sessions` endpoint for debugging/demo
purposes.  It lists active sessions and their expiry times.
"""

from __future__ import annotations

import os
import base64
import uuid
from datetime import datetime, timedelta
from typing import Dict, Optional, Tuple

from flask import Flask, request, jsonify, abort
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


app = Flask(__name__)

# Directory where RSA key files are persisted.  Can be overridden
# by setting the KEY_DIR environment variable.  When run under
# Docker this directory is mounted from a named volume.
KEY_DIR = os.environ.get("KEY_DIR", "keys")
PRIVATE_KEY_PATH = os.path.join(KEY_DIR, "private_key.pem")
PUBLIC_KEY_PATH = os.path.join(KEY_DIR, "public_key.pem")

# In‑memory session store mapping session IDs to AES keys and
# expiry times.  In a production system this might be stored in
# Redis or a database.  Keys expire automatically based on the TTL.
sessions: Dict[str, Dict[str, any]] = {}


def load_or_generate_keys() -> Tuple[rsa.RSAPrivateKey, rsa.RSAPublicKey]:
    """Load an existing RSA key pair from disk or generate a new one.

    Keys are stored in PEM files within KEY_DIR.  If the files
    exist they are loaded; otherwise a new 2048‑bit key pair is
    generated and written to disk.  Returns the private and
    corresponding public key.
    """
    if not os.path.exists(KEY_DIR):
        os.makedirs(KEY_DIR)
    if os.path.exists(PRIVATE_KEY_PATH) and os.path.exists(PUBLIC_KEY_PATH):
        # Load existing keys
        with open(PRIVATE_KEY_PATH, 'rb') as f:
            private_key = serialization.load_pem_private_key(f.read(), password=None)
        with open(PUBLIC_KEY_PATH, 'rb') as f:
            public_key = serialization.load_pem_public_key(f.read())
    else:
        # Generate new keys
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        public_key = private_key.public_key()
        # Persist the private key
        with open(PRIVATE_KEY_PATH, 'wb') as f:
            f.write(
                private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption(),
                )
            )
        # Persist the public key
        with open(PUBLIC_KEY_PATH, 'wb') as f:
            f.write(
                public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo,
                )
            )
    return private_key, public_key


# Initialise keys on module load
private_key, public_key = load_or_generate_keys()


def get_session(session_id: str) -> Optional[Dict[str, any]]:
    """Retrieve a session by ID if it exists and is not expired.

    Expired sessions are removed from the store.  Returns None if
    the session does not exist or has expired.
    """
    session = sessions.get(session_id)
    if not session:
        return None
    if session['expires_at'] < datetime.utcnow():
        # Clean up expired session
        del sessions[session_id]
        return None
    return session


@app.route('/public-key', methods=['GET'])
def get_public_key():
    """Return the public key and metadata as JSON."""
    pem_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return jsonify({
        "algorithm": "RSA",
        "size": 2048,
        "key": pem_bytes.decode('utf-8'),
    })


@app.route('/handshake', methods=['POST'])
def handshake():
    """Accept an RSA‑encrypted AES key and establish a session.

    Clients send a JSON object with a single field `key` containing
    the base64‑encoded ciphertext.  The server decrypts the
    ciphertext using its private key, stores the resulting AES key
    with a one hour expiry and returns a new session ID along with
    the ISO‑formatted expiry timestamp.  Invalid payloads result in
    a 400 Bad Request.
    """
    data = request.get_json(force=True, silent=True) or {}
    enc_key_b64 = data.get('key')
    if not enc_key_b64:
        abort(400, description="Missing encrypted key")
    try:
        encrypted_key = base64.b64decode(enc_key_b64)
        # Decrypt with OAEP using SHA‑256
        aes_key = private_key.decrypt(
            encrypted_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )
    except Exception:
        abort(400, description="Invalid encrypted key")
    # Create a new session
    session_id = str(uuid.uuid4())
    expires_at = datetime.utcnow() + timedelta(hours=1)
    sessions[session_id] = {
        "key": aes_key,
        "expires_at": expires_at,
    }
    return jsonify({
        "session_id": session_id,
        "expires_at": expires_at.isoformat() + 'Z',
    })


@app.route('/message', methods=['POST'])
def message():
    """Decrypt an incoming AES‑GCM encrypted message and send a response.

    Requires a valid `X-Session-ID` header containing a session ID
    returned from the handshake endpoint.  The body must include
    base64‑encoded `ciphertext`, `nonce` and `tag` fields.  The
    server decrypts the payload, processes the plaintext (here we
    simply convert it to uppercase) and returns a new JSON object
    containing encrypted `ciphertext`, `nonce` and `tag`.
    """
    session_id = request.headers.get('X-Session-ID')
    if not session_id:
        abort(401, description="Missing X-Session-ID header")
    session = get_session(session_id)
    if not session:
        abort(401, description="Invalid or expired session")
    data = request.get_json(force=True, silent=True) or {}
    ciphertext_b64 = data.get('ciphertext')
    nonce_b64 = data.get('nonce')
    tag_b64 = data.get('tag')
    if not ciphertext_b64 or not nonce_b64 or not tag_b64:
        abort(400, description="Missing ciphertext, nonce or tag")
    try:
        aes_key: bytes = session['key']
        aesgcm = AESGCM(aes_key)
        ciphertext = base64.b64decode(ciphertext_b64)
        nonce = base64.b64decode(nonce_b64)
        tag = base64.b64decode(tag_b64)
        # AESGCM.decrypt expects the tag appended to the ciphertext
        plaintext = aesgcm.decrypt(nonce, ciphertext + tag, None)
    except Exception:
        abort(400, description="Decryption failed")
    # Process the message – for demonstration we convert it to upper case
    response_text = plaintext.decode('utf-8').upper()
    response_bytes = response_text.encode('utf-8')
    # Encrypt the response
    new_nonce = os.urandom(12)  # 96‑bit nonce for GCM
    ct_and_tag = AESGCM(aes_key).encrypt(new_nonce, response_bytes, None)
    ct, tag = ct_and_tag[:-16], ct_and_tag[-16:]
    return jsonify({
        "ciphertext": base64.b64encode(ct).decode('utf-8'),
        "nonce": base64.b64encode(new_nonce).decode('utf-8'),
        "tag": base64.b64encode(tag).decode('utf-8'),
    })


@app.route('/sessions', methods=['GET'])
def list_sessions():
    """Return a list of active sessions and their expiry times.

    This endpoint is intentionally left unsecured for demonstration
    purposes.  In a real‑world application you would restrict
    access to this information.
    """
    now = datetime.utcnow()
    active = {}
    # Clean up expired sessions while building the response
    for sid, session in list(sessions.items()):
        if session['expires_at'] < now:
            del sessions[sid]
            continue
        active[sid] = {"expires_at": session['expires_at'].isoformat() + 'Z'}
    return jsonify(active)


if __name__ == '__main__':
    # When run directly, start the development server.  In
    # production the Dockerfile uses gunicorn to serve this app.
    app.run(host='0.0.0.0', port=5000)