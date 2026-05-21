"""Symmetric encryption for mailbox passwords stored on the Migration model.

The Fernet key lives in ``settings.MAILBOX_FERNET_KEY`` (loaded from .env).
Rotating the key makes every existing encrypted value unreadable, so treat
it like SECRET_KEY: never commit, never rotate without re-saving every form.
"""

from __future__ import annotations

from cryptography.fernet import Fernet, InvalidToken
from django.conf import settings


def _fernet() -> Fernet:
    key = settings.MAILBOX_FERNET_KEY
    if not key:
        raise RuntimeError(
            "MAILBOX_FERNET_KEY is not set. Generate one with:\n"
            "  python -c \"from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())\"\n"
            "and add it to .env"
        )
    return Fernet(key.encode() if isinstance(key, str) else key)


def encrypt(plaintext: str) -> bytes:
    if not plaintext:
        return b""
    return _fernet().encrypt(plaintext.encode("utf-8"))


def decrypt(ciphertext: bytes) -> str:
    if not ciphertext:
        return ""
    try:
        return _fernet().decrypt(bytes(ciphertext)).decode("utf-8")
    except InvalidToken:
        # Wrong key or corrupted data — treat as "no credentials" rather than crash.
        return ""
