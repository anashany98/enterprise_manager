import base64
import hashlib
import os
from typing import Optional

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from flask import current_app

NONCE_SIZE = 12  # 96-bit nonce recommended for AES-GCM


def _load_config_key() -> str:
    if current_app:
        config_key = current_app.config.get("ENCRYPTION_KEY")
        if config_key:
            return config_key
    return os.getenv("ENCRYPTION_KEY", "")


def load_key(raw_key: Optional[str] = None) -> bytes:
    """Load the AES key from environment or explicit value."""
    candidate = raw_key or _load_config_key()
    if not candidate:
        raise RuntimeError(
            "ENCRYPTION_KEY is not set. Please define it in the environment or .env file."
        )

    decoded: Optional[bytes] = None
    # Try URL-safe base64 first (recommended format)
    try:
        decoded = base64.urlsafe_b64decode(candidate)
    except Exception:
        decoded = None

    # Fallback: plain base64
    if decoded is None:
        try:
            decoded = base64.b64decode(candidate)
        except Exception:
            decoded = None

    if decoded and len(decoded) == 32:
        return decoded

    if len(candidate) == 32:
        # Assume already a 32-byte key (unlikely for text env vars but possible if generated)
        return candidate.encode("utf-8")

    # Fallback to deterministic SHA-256 of provided plaintext secret
    return hashlib.sha256(candidate.encode("utf-8")).digest()


def encrypt_password(plain_text: str, *, key: Optional[bytes] = None) -> bytes:
    """Encrypt a plaintext password with AES-256-GCM."""
    if plain_text is None:
        raise ValueError("plain_text cannot be None")

    key_bytes = key or load_key()
    aesgcm = AESGCM(key_bytes)
    nonce = os.urandom(NONCE_SIZE)
    cipher_text = aesgcm.encrypt(nonce, plain_text.encode("utf-8"), None)
    return nonce + cipher_text


def decrypt_password(cipher_payload: bytes, *, key: Optional[bytes] = None) -> str:
    """Decrypt an AES-256-GCM payload and return the plaintext password."""
    if cipher_payload is None:
        return ""

    key_bytes = key or load_key()
    nonce = cipher_payload[:NONCE_SIZE]
    cipher_text = cipher_payload[NONCE_SIZE:]
    aesgcm = AESGCM(key_bytes)
    plain_bytes = aesgcm.decrypt(nonce, cipher_text, None)
    return plain_bytes.decode("utf-8")


def encrypt_blob(data: bytes, *, key: Optional[bytes] = None) -> bytes:
    """Encrypt arbitrary bytes with AES-256-GCM (used for backups)."""
    key_bytes = key or load_key()
    aesgcm = AESGCM(key_bytes)
    nonce = os.urandom(NONCE_SIZE)
    cipher_text = aesgcm.encrypt(nonce, data, None)
    return nonce + cipher_text


def decrypt_blob(cipher_payload: bytes, *, key: Optional[bytes] = None) -> bytes:
    """Decrypt payload produced by encrypt_blob."""
    if cipher_payload is None:
        return b""
    key_bytes = key or load_key()
    nonce = cipher_payload[:NONCE_SIZE]
    cipher_text = cipher_payload[NONCE_SIZE:]
    aesgcm = AESGCM(key_bytes)
    return aesgcm.decrypt(nonce, cipher_text, None)


def encode_for_storage(data: bytes) -> str:
    """Encode bytes into URL-safe base64 for JSON/API responses."""
    return base64.urlsafe_b64encode(data).decode("utf-8")


def decode_from_storage(data: str) -> bytes:
    """Decode previously encoded data from encode_for_storage."""
    return base64.urlsafe_b64decode(data.encode("utf-8"))
