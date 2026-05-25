"""
Tests for the crypto module.
"""
import os
import base64
import hashlib
import pytest
from cryptography.fernet import Fernet
from crypto import encrypt, decrypt


class TestEncryptDecrypt:
    def test_roundtrip(self):
        original = "my-secret-password"
        encrypted = encrypt(original)
        assert encrypted != original
        assert encrypted.startswith("gAAAAA")
        decrypted = decrypt(encrypted)
        assert decrypted == original

    def test_empty_string(self):
        assert encrypt("") == ""
        assert decrypt("") == ""

    def test_different_keys_produce_different_ciphertexts(self):
        encrypted1 = encrypt("password")
        encrypted2 = encrypt("password")
        assert encrypted1 != encrypted2

    def test_decrypt_with_wrong_key_raises(self):
        encrypted = encrypt("test")
        os.environ["ENCRYPTION_KEY"] = "different-encryption-key-for-this-test"
        with pytest.raises(ValueError, match="Failed to decrypt"):
            decrypt(encrypted)

    def test_decrypt_falls_back_to_secret_key(self):
        old_encrypt_key = os.environ.pop("ENCRYPTION_KEY", None)
        old_secret_key = os.environ.get("SECRET_KEY")
        os.environ["SECRET_KEY"] = "legacy-secret-key"
        try:
            legacy_key = "legacy-secret-key"
            # encrypt manually with the legacy key derivation
            derived = base64.urlsafe_b64encode(hashlib.sha256(legacy_key.encode()).digest())
            token = Fernet(derived).encrypt(b"password")
            assert decrypt(token.decode()) == "password"
        finally:
            if old_encrypt_key is not None:
                os.environ["ENCRYPTION_KEY"] = old_encrypt_key
            elif "ENCRYPTION_KEY" in os.environ:
                os.environ.pop("ENCRYPTION_KEY")
            if old_secret_key is not None:
                os.environ["SECRET_KEY"] = old_secret_key
            else:
                os.environ.pop("SECRET_KEY", None)
