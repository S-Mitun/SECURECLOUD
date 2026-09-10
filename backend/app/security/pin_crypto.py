"""
SecureCloud - Confidential File Vault Cryptography Engine
PBKDF2-HMAC-SHA256 key derivation and AES-GCM-256 authenticated encryption.
"""

import os
import base64
from typing import Tuple
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import bcrypt

def derive_key_from_pin(pin: str, salt: bytes) -> bytes:
    """Derives a 256-bit AES key from a user PIN/password using PBKDF2."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100_000
    )
    return kdf.derive(pin.encode("utf-8"))

def hash_pin(pin: str) -> Tuple[str, str]:
    """Generates a salt and bcrypt hash for the PIN."""
    salt = os.urandom(16)
    salt_b64 = base64.b64encode(salt).decode("utf-8")
    pin_hash = bcrypt.hashpw(pin.encode("utf-8"), bcrypt.gensalt(12)).decode("utf-8")
    return salt_b64, pin_hash

def verify_pin_hash(pin: str, pin_hash: str) -> bool:
    """Verifies a PIN against bcrypt hash."""
    try:
        return bcrypt.checkpw(pin.encode("utf-8"), pin_hash.encode("utf-8"))
    except Exception:
        return False

def encrypt_file_data(data: bytes, pin: str, salt_b64: str) -> bytes:
    """Encrypts byte data with AES-256-GCM using key derived from PIN."""
    salt = base64.b64decode(salt_b64.encode("utf-8"))
    key = derive_key_from_pin(pin, salt)
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, data, None)
    # Return nonce + ciphertext combined
    return nonce + ciphertext

def decrypt_file_data(encrypted_data: bytes, pin: str, salt_b64: str) -> bytes:
    """Decrypts byte data with AES-256-GCM using key derived from PIN."""
    if len(encrypted_data) < 28:
        raise ValueError("Encrypted data payload is too short or malformed.")
    salt = base64.b64decode(salt_b64.encode("utf-8"))
    key = derive_key_from_pin(pin, salt)
    aesgcm = AESGCM(key)
    nonce = encrypted_data[:12]
    ciphertext = encrypted_data[12:]
    return aesgcm.decrypt(nonce, ciphertext, None)
