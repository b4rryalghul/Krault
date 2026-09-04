"""Security manager for encryption and key management"""
import logging
import base64
import os
import hmac
from typing import Optional


from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag

from argon2.low_level import hash_secret_raw, Type as _Argon2Type

# AES-256-GCM constants
_NONCE_SIZE = 12   # 96-bit nonce recommended for GCM
_KEY_SIZE   = 32   # 256-bit key


class SecurityManager:
    def __init__(self):
        self._key = None #placeholder
        self.current_user = None
        self.kdf = None   # which KDF derived the current key: "argon2id"


    # Key derivation
    def generate_salt(self) -> bytes:
        """Generate a cryptographically secure random salt."""
        return os.urandom(32)

    def initialize_encryption(self, password: str, username: str, salt: bytes,
                               kdf: str = "argon2id") -> bool:
        """ Derive a 256-bit AES key from the master password and store it for subsequent encrypt/decrypt calls """
        try:
            from config.constants import (
                ARGON2_TIME_COST,
                ARGON2_MEMORY_COST,
                ARGON2_PARALLELISM,
                ARGON2_HASH_LEN,
            )

            if kdf != "argon2id":
                raise ValueError(f"Unsupported KDF: {kdf!r}")

            key = hash_secret_raw(
                secret=password.encode('utf-8'),
                salt=salt,
                time_cost=ARGON2_TIME_COST,
                memory_cost=ARGON2_MEMORY_COST,
                parallelism=ARGON2_PARALLELISM,
                hash_len=ARGON2_HASH_LEN,
                type=_Argon2Type.ID,
            )

            self._key = bytearray(key) # Create mutable bytearray from key

            self.current_user = username
            self.kdf = kdf
            logging.info(f"Encryption initialised for user '{username}' (kdf={kdf})")
            return True
        except Exception as e:
            logging.error(f"Encryption initialisation error: {e}")
            return False


    @property
    def encryption_key(self) -> bytes:
        if self._key is None:
            raise RuntimeError("Encryption key not initialised")
        return bytes(self._key)

    # Encrypt / Decrypt  (AES-256-GCM)
    def encrypt_data(self, data: str) -> str:
        """ Encrypt a plaintext string with AES-256-GCM """
        if self._key is None:
            raise RuntimeError("Encryption key not initialised")

        nonce = os.urandom(_NONCE_SIZE)
        ciphertext = AESGCM(self.encryption_key).encrypt(nonce, data.encode('utf-8'), None)
        # Prepend nonce so decrypt() is self-contained
        return base64.b64encode(nonce + ciphertext).decode('ascii')

    def decrypt_data(self, encrypted_data: str) -> str:
        """ Decrypt an AES-256-GCM ciphertext produced by encrypt_data() """
        if self._key is None:
            raise RuntimeError("Encryption key not initialised")

        try:
            raw = base64.b64decode(encrypted_data)
            if len(raw) < _NONCE_SIZE + 16:   # nonce + minimum GCM tag
                logging.error("Ciphertext too short — data may be corrupted")
                return None

            nonce      = raw[:_NONCE_SIZE]
            ciphertext = raw[_NONCE_SIZE:]
            plaintext  = AESGCM(self.encryption_key).decrypt(nonce, ciphertext, None)
            return plaintext.decode('utf-8')

        except InvalidTag:
            # Authentication failure — wrong key or tampered ciphertext
            logging.error("AES-GCM authentication failed: wrong password or corrupted data")
            return None
        except Exception as e:
            logging.error(f"Decryption error: {e}")
            return None


    """ Password verification"""
    _SENTINEL = "pm2:password_verification_sentinel_v1"

    def create_password_verifier(self) -> str:
        """ Encrypt the sentinel with the current session key and return the ciphertext """
        if self._key is None:
            raise RuntimeError("Key not initialised — call initialize_encryption() first")
        return self.encrypt_data(self._SENTINEL)

    def verify_password(self, stored_verifier: str) -> bool:
        """ Verify the already-derived session key against a stored verifier blob.
        Uses this instance's existing key (set by initialize_encryption) rather
        than re-deriving via Argon2id — the caller is expected to have already
        called initialize_encryption() with the candidate password. """
        if self._key is None:
            logging.error("Password verification error: key not initialised")
            return False
        try:
            decrypted = self.decrypt_data(stored_verifier)

            # hmac.compare_digest protects against timing attacks
            if decrypted is None:
                return False
            return hmac.compare_digest(decrypted, self._SENTINEL)
        except Exception as e:
            logging.error(f"Password verification error: {e}")
            return False

    # Session helpers
    def generate_session_token(self) -> str:
        """ Generate a cryptographically secure random session token """
        return base64.b64encode(os.urandom(32)).decode('ascii')

    def invalidate_session(self) -> None:
        """ Clear the in-memory encryption key and current user """
        if self._key is not None:
            for i in range(len(self._key)):
                self._key[i] = 0
            self._key = None
        self.current_user = None
        self.kdf = None

    # Constant-time comparison
    def constant_time_compare(self, val1: str, val2: str) -> bool:
        """ Compare two strings in constant time using hmac.compare_digest() to prevent timing side-channel attacks """
        try:
            return hmac.compare_digest(
                val1.encode('utf-8'),
                val2.encode('utf-8'),
            )
        except Exception as e:
            logging.error(f"Constant-time comparison error: {e}")
            return False