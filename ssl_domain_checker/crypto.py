import base64
import hashlib
import logging
import os
from cryptography.fernet import Fernet, InvalidToken

logger = logging.getLogger(__name__)


def _derive_key(raw):
    return base64.urlsafe_b64encode(hashlib.sha256(raw.encode()).digest())


def _get_key():
    raw = os.environ.get('ENCRYPTION_KEY')
    if not raw:
        raise ValueError("ENCRYPTION_KEY must be set for encryption")
    return _derive_key(raw)


def _get_legacy_key():
    raw = os.environ.get('SECRET_KEY')
    if not raw:
        return None
    return _derive_key(raw)


def encrypt(plaintext):
    if not plaintext:
        return ''
    return Fernet(_get_key()).encrypt(plaintext.encode()).decode()


def decrypt(ciphertext):
    if not ciphertext:
        return ''
    # Try current encryption key first if configured.
    if os.environ.get('ENCRYPTION_KEY'):
        try:
            return Fernet(_get_key()).decrypt(ciphertext.encode()).decode()
        except InvalidToken:
            pass
    # Fall back to legacy SECRET_KEY for backward compatibility if available.
    legacy_key = _get_legacy_key()
    if legacy_key is not None:
        logger.warning(
            "Decrypting with SECRET_KEY (legacy). Set ENCRYPTION_KEY and re-encrypt secrets. "
            "See https://opencode.ai for migration instructions."
        )
        try:
            return Fernet(legacy_key).decrypt(ciphertext.encode()).decode()
        except InvalidToken:
            pass
    raise ValueError("Failed to decrypt ciphertext: invalid encryption key or corrupted data")
