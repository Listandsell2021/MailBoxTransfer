"""Remembering mailbox passwords per user, so one is typed once.

Every screen that asks for a mailbox password calls `remember()` with what the
user typed and `recall()` when the field was left blank. The store is keyed by
(owner, host, username) and holds the same Fernet-encrypted bytes the job rows
hold, so this adds no new exposure — only fewer chances to end up with no
password at all.
"""

from __future__ import annotations

from .crypto import decrypt, encrypt
from .models import MailboxCredential


def _norm(host: str, username: str) -> tuple[str, str]:
    """Host is case-insensitive, usernames are not; both get trimmed."""
    return (host or "").strip().lower(), (username or "").strip()


def remember(owner_id: int | None, host: str, username: str, password: str) -> None:
    """Save (or replace) the password for one mailbox. No-op for blanks."""
    if not owner_id or not password:
        return
    h, u = _norm(host, username)
    if not h or not u:
        return
    MailboxCredential.objects.update_or_create(
        owner_id=owner_id, host=h, username=u,
        defaults={"password_enc": encrypt(password)},
    )


def recall(owner_id: int | None, host: str, username: str) -> str:
    """The saved password for one mailbox, or "" when there is none.

    Returns "" for a row this host cannot decrypt as well, which is what
    `decrypt` does with a key that does not match.
    """
    if not owner_id:
        return ""
    h, u = _norm(host, username)
    if not h or not u:
        return ""
    row = (
        MailboxCredential.objects
        .filter(owner_id=owner_id, host=h, username=u)
        .only("password_enc").first()
    )
    return decrypt(bytes(row.password_enc)) if row else ""
