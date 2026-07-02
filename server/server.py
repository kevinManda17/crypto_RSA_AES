"""Flask application implementing a simple RSA/AES handshake.

This server exposes three endpoints:

* `GET /public-key` – returns the RSA public key in PEM format and
  metadata.  Clients must fetch this to encrypt their AES key.
* `POST /handshake` – accepts a JSON object with a `client_id` and
  an RSA‑encrypted AES‑256 session key (base64 encoded).  The server
  decrypts the key, creates a new session identifier and stores the
  client ID with the symmetric key and a one hour expiry.  The
  response contains the session identifier and the expiry timestamp.
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
import logging
from datetime import datetime, timedelta
from typing import Any, Dict, Optional, Tuple

from flask import Flask, request, jsonify, abort, g
from werkzeug.exceptions import HTTPException
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


app = Flask(__name__)
logging.basicConfig(level=os.environ.get("LOG_LEVEL", "INFO"))

# Directory where RSA key files are persisted.  Can be overridden
# by setting the KEY_DIR environment variable.  When run under
# Docker this directory is mounted from a named volume.
KEY_DIR = os.environ.get("KEY_DIR", "keys")
PRIVATE_KEY_PATH = os.path.join(KEY_DIR, "private_key.pem")
PUBLIC_KEY_PATH = os.path.join(KEY_DIR, "public_key.pem")

# In-memory session store mapping session IDs to client IDs, AES keys
# and expiry times. In a production system this might be stored in Redis
# or a database. Keys expire automatically based on the TTL.
sessions: Dict[str, Dict[str, Any]] = {}

# Endpoints protected by the session middleware. They require a valid
# X-Session-ID header and an AES-GCM encrypted JSON payload.
PROTECTED_ENDPOINTS = {"/message"}


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
        os.chmod(PRIVATE_KEY_PATH, 0o600)
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


def get_session(session_id: str) -> Optional[Dict[str, Any]]:
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


def decode_b64_field(data: Dict[str, Any], field_name: str) -> bytes:
    """Decode a required base64 field from a JSON object."""
    value = data.get(field_name)
    if not value:
        abort(400, description=f"Missing {field_name}")
    try:
        return base64.b64decode(value, validate=True)
    except Exception:
        abort(400, description=f"Invalid base64 for {field_name}")


def log_unauthenticated_attempt(reason: str, session_id: Optional[str] = None) -> None:
    """Log an unauthenticated access attempt for audit/demo purposes."""
    app.logger.warning(
        "Unauthenticated request rejected: path=%s reason=%s session_id=%s remote_addr=%s",
        request.path,
        reason,
        session_id or "-",
        request.remote_addr or "-",
    )


def log_success(action: str, **fields: Any) -> None:
    """Log a successful operation for demo/audit visibility."""
    details = " ".join(f"{key}={value}" for key, value in fields.items())
    app.logger.info(
        "%s: path=%s %s remote_addr=%s",
        action,
        request.path,
        details,
        request.remote_addr or "-",
    )


@app.errorhandler(HTTPException)
def handle_http_exception(exc: HTTPException):
    """Return API errors as JSON instead of Flask's default HTML pages."""
    response = jsonify({
        "error": exc.description,
        "status_code": exc.code,
    })
    response.status_code = exc.code or 500
    return response


@app.before_request
def decrypt_protected_request():
    """Verify the session and decrypt protected AES-GCM request bodies."""
    if request.path not in PROTECTED_ENDPOINTS:
        return None

    session_id = request.headers.get('X-Session-ID')
    if not session_id:
        log_unauthenticated_attempt("missing X-Session-ID")
        abort(401, description="Missing X-Session-ID header")

    session = get_session(session_id)
    if not session:
        log_unauthenticated_attempt("invalid or expired session", session_id)
        abort(401, description="Invalid or expired session")

    data = request.get_json(force=True, silent=True) or {}
    ciphertext = decode_b64_field(data, 'ciphertext')
    nonce = decode_b64_field(data, 'nonce')
    tag = decode_b64_field(data, 'tag')

    try:
        aes_key: bytes = session['key']
        plaintext = AESGCM(aes_key).decrypt(nonce, ciphertext + tag, None)
    except Exception:
        app.logger.warning(
            "Encrypted request rejected: path=%s reason=decryption failed session_id=%s client_id=%s remote_addr=%s",
            request.path,
            session_id,
            session.get("client_id", "-"),
            request.remote_addr or "-",
        )
        abort(400, description="Decryption failed")

    log_success(
        "Session validated",
        session_id=session_id,
        client_id=session.get("client_id", "-"),
    )

    g.session_id = session_id
    g.session = session
    g.aes_key = session['key']
    g.plaintext = plaintext
    return None


@app.route('/public-key', methods=['GET'])
def get_public_key():
    """Return the public key and metadata as JSON."""
    pem_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    log_success("Public key served")
    return jsonify({
        "algorithm": "RSA",
        "size": 2048,
        "key": pem_bytes.decode('utf-8'),
    })


@app.route('/handshake', methods=['POST'])
def handshake():
    """Accept an RSA‑encrypted AES key and establish a session.

    Clients send a JSON object containing `client_id` and
    `encrypted_session_key`.  The server decrypts the ciphertext using
    its private key, stores the resulting AES-256 key with a one hour
    expiry and returns a new session ID along with the ISO-formatted
    expiry timestamp. Invalid payloads result in a 400 Bad Request.
    """
    data = request.get_json(force=True, silent=True) or {}
    client_id = data.get('client_id')
    if not isinstance(client_id, str) or not client_id.strip():
        abort(400, description="Missing client_id")
    client_id = client_id.strip()

    encrypted_key = decode_b64_field(data, 'encrypted_session_key')
    try:
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

    if len(aes_key) != 32:
        abort(400, description="Invalid AES-256 key length")

    # Create a new session
    session_id = str(uuid.uuid4())
    expires_at = datetime.utcnow() + timedelta(hours=1)
    sessions[session_id] = {
        "client_id": client_id,
        "key": aes_key,
        "expires_at": expires_at,
    }
    log_success(
        "Handshake established",
        client_id=client_id,
        session_id=session_id,
        expires_at=expires_at.isoformat() + 'Z',
    )
    return jsonify({
        "status": "ok",
        "client_id": client_id,
        "session_id": session_id,
        "expires_at": expires_at.isoformat() + 'Z',
    })


@app.route('/message', methods=['POST'])
def message():
    """Decrypt an incoming AES‑GCM encrypted message and send a response.

    Requires a valid `X-Session-ID` header containing a session ID
    returned from the handshake endpoint.  Session verification and
    request decryption are handled by `decrypt_protected_request`.
    This route processes the plaintext and returns a new JSON object
    containing encrypted `ciphertext`, `nonce` and `tag`.
    """
    # Process the message – for demonstration we convert it to upper case
    response_text = g.plaintext.decode('utf-8').upper()
    response_bytes = response_text.encode('utf-8')
    # Encrypt the response
    new_nonce = os.urandom(12)  # 96‑bit nonce for GCM
    ct_and_tag = AESGCM(g.aes_key).encrypt(new_nonce, response_bytes, None)
    ct, tag = ct_and_tag[:-16], ct_and_tag[-16:]
    log_success(
        "Message processed",
        session_id=g.session_id,
        client_id=g.session.get("client_id", "-"),
    )
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
        active[sid] = {
            "client_id": session.get("client_id"),
            "expires_at": session['expires_at'].isoformat() + 'Z',
        }
    return jsonify(active)


if __name__ == '__main__':
    # When run directly, start the development server.  In
    # production the Dockerfile uses gunicorn to serve this app.
    app.run(host='0.0.0.0', port=5000)
