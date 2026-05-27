"""Thin wrapper over imaplib for the operations the migrator needs.

Uses IMAP4_SSL by default. All folder names are passed and returned as
unicode strings; encoding to modified UTF-7 is done at the boundary.
"""

from __future__ import annotations

import imaplib
import re
import ssl
import time
from dataclasses import dataclass, field
from typing import Iterator


SPECIAL_USE_FLAGS = {
    "\\Inbox", "\\Sent", "\\Drafts", "\\Trash", "\\Junk", "\\Archive",
    "\\All", "\\Flagged", "\\Important",
}


@dataclass
class FolderInfo:
    name: str
    flags: list[str] = field(default_factory=list)
    delimiter: str = "/"

    @property
    def special_use(self) -> str:
        for f in self.flags:
            if f in SPECIAL_USE_FLAGS:
                return f
        # INBOX is implicitly the inbox
        if self.name.upper() == "INBOX":
            return "\\Inbox"
        return ""


# ---------------------------------------------------------------------------
# modified UTF-7 (RFC 3501 §5.1.3) for non-ASCII folder names
# imaplib doesn't ship encoders for this, so we provide minimal ones.
# ---------------------------------------------------------------------------

def _mutf7_encode(name: str) -> bytes:
    out = bytearray()
    buf: list[str] = []

    def flush_buf() -> None:
        if not buf:
            return
        s = "".join(buf).encode("utf-16-be")
        import base64
        b64 = base64.b64encode(s).rstrip(b"=").replace(b"/", b",")
        out.extend(b"&" + b64 + b"-")
        buf.clear()

    for ch in name:
        code = ord(ch)
        if 0x20 <= code <= 0x7E:
            flush_buf()
            if ch == "&":
                out.extend(b"&-")
            else:
                out.append(code)
        else:
            buf.append(ch)
    flush_buf()
    return bytes(out)


def _mutf7_decode(data: bytes | str) -> str:
    if isinstance(data, str):
        b = data.encode("ascii", errors="replace")
    else:
        b = data
    import base64
    out: list[str] = []
    i = 0
    while i < len(b):
        c = b[i:i + 1]
        if c == b"&":
            j = b.find(b"-", i + 1)
            if j == -1:
                out.append(b[i:].decode("ascii", "replace"))
                break
            chunk = b[i + 1:j]
            if not chunk:
                out.append("&")
            else:
                pad = b"=" * (-len(chunk) % 4)
                decoded = base64.b64decode(chunk.replace(b",", b"/") + pad)
                out.append(decoded.decode("utf-16-be", "replace"))
            i = j + 1
        else:
            out.append(c.decode("ascii", "replace"))
            i += 1
    return "".join(out)


# Quote a folder name for the IMAP wire (mutf-7, then RFC3501 quoted string)
def _imap_quote(name: str) -> bytes:
    encoded = _mutf7_encode(name)
    return b'"' + encoded.replace(b'\\', b'\\\\').replace(b'"', b'\\"') + b'"'


# ---------------------------------------------------------------------------
# Client
# ---------------------------------------------------------------------------


class ImapError(Exception):
    pass


class ImapClient:
    def __init__(self, host: str, port: int, username: str, password: str, use_ssl: bool = True):
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.use_ssl = use_ssl
        self._conn: imaplib.IMAP4 | None = None

    def __enter__(self) -> "ImapClient":
        self.connect()
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()

    def connect(self) -> None:
        # Shared mail hosts (Kasserver, IONOS, Strato, …) commonly return
        # [AUTHENTICATIONFAILED] when a recent session for the same account
        # hasn't been reaped yet, even though credentials are correct.
        # Retry a couple of times with backoff before giving up.
        backoffs = [0, 3, 7]
        last_err: Exception | None = None
        for delay in backoffs:
            if delay:
                time.sleep(delay)
            try:
                if self.use_ssl:
                    ctx = ssl.create_default_context()
                    self._conn = imaplib.IMAP4_SSL(self.host, self.port, ssl_context=ctx)
                else:
                    self._conn = imaplib.IMAP4(self.host, self.port)
                typ, data = self._conn.login(self.username, self.password)
                if typ == "OK":
                    return
                last_err = ImapError(f"LOGIN failed: {data!r}")
            except (imaplib.IMAP4.error, OSError) as exc:
                last_err = exc
            # Clean up the half-open socket before retrying.
            if self._conn is not None:
                try:
                    self._conn.shutdown()
                except Exception:
                    pass
                self._conn = None
        raise last_err if last_err else ImapError("LOGIN failed: unknown error")

    def close(self) -> None:
        if not self._conn:
            return
        try:
            try:
                self._conn.close()
            except Exception:
                pass
            self._conn.logout()
        except Exception:
            pass
        self._conn = None

    @property
    def conn(self) -> imaplib.IMAP4:
        if not self._conn:
            raise ImapError("Not connected")
        return self._conn

    # -- folders ------------------------------------------------------------

    _LIST_RE = re.compile(rb'\((?P<flags>[^)]*)\) "(?P<delim>[^"]*)" (?P<name>.+)$')

    def list_folders(self) -> list[FolderInfo]:
        typ, data = self.conn.list()
        if typ != "OK":
            raise ImapError(f"LIST failed: {data!r}")
        out: list[FolderInfo] = []
        for raw in data:
            if raw is None:
                continue
            line = raw if isinstance(raw, bytes) else raw.encode("utf-8", "replace")
            m = self._LIST_RE.match(line)
            if not m:
                continue
            flags = m.group("flags").decode("ascii", "replace").split()
            delim = m.group("delim").decode("ascii", "replace") or "/"
            name_raw = m.group("name").strip()
            if name_raw.startswith(b'"') and name_raw.endswith(b'"'):
                name_raw = name_raw[1:-1]
            name = _mutf7_decode(name_raw)
            out.append(FolderInfo(name=name, flags=flags, delimiter=delim))
        return out

    def select(self, folder: str, readonly: bool = True) -> int:
        typ, data = self.conn.select(_imap_quote(folder), readonly=readonly)
        if typ != "OK":
            raise ImapError(f"SELECT {folder!r} failed: {data!r}")
        try:
            return int(data[0])
        except (ValueError, IndexError):
            return 0

    def create_folder(self, folder: str) -> None:
        typ, data = self.conn.create(_imap_quote(folder))
        if typ != "OK" and b"ALREADYEXISTS" not in (data[0] if data else b""):
            raise ImapError(f"CREATE {folder!r} failed: {data!r}")
        try:
            self.conn.subscribe(_imap_quote(folder))
        except Exception:
            pass

    # -- messages -----------------------------------------------------------

    def search_all_uids(self) -> list[int]:
        typ, data = self.conn.uid("SEARCH", None, "ALL")
        if typ != "OK":
            raise ImapError(f"SEARCH failed: {data!r}")
        if not data or not data[0]:
            return []
        return [int(x) for x in data[0].split()]

    def fetch_message(self, uid: int) -> tuple[bytes, list[str], str | None]:
        """Return (raw rfc822, flags, internaldate-string) for a UID."""
        typ, data = self.conn.uid("FETCH", str(uid), "(RFC822 FLAGS INTERNALDATE)")
        if typ != "OK" or not data:
            raise ImapError(f"FETCH {uid} failed: {data!r}")

        raw = b""
        flags: list[str] = []
        internaldate: str | None = None

        for item in data:
            if isinstance(item, tuple) and len(item) >= 2:
                header = item[0]
                raw = item[1]
                if isinstance(header, bytes):
                    text = header.decode("ascii", "replace")
                    fm = re.search(r"FLAGS \(([^)]*)\)", text)
                    if fm:
                        flags = fm.group(1).split()
                    dm = re.search(r'INTERNALDATE "([^"]+)"', text)
                    if dm:
                        internaldate = dm.group(1)
        if not raw:
            raise ImapError(f"FETCH {uid} returned no body")
        return raw, flags, internaldate

    def fetch_message_ids(self) -> dict[int, str]:
        """UID -> Message-ID for the currently-selected mailbox."""
        typ, data = self.conn.uid("FETCH", "1:*", "(BODY.PEEK[HEADER.FIELDS (MESSAGE-ID)])")
        if typ != "OK" or not data:
            return {}
        out: dict[int, str] = {}
        cur_uid: int | None = None
        for item in data:
            if isinstance(item, tuple) and len(item) >= 2:
                header = item[0]
                body = item[1]
                if isinstance(header, bytes):
                    m = re.search(rb"(\d+) \(UID (\d+)", header)
                    if m:
                        cur_uid = int(m.group(2))
                if cur_uid is not None and isinstance(body, (bytes, bytearray)):
                    text = bytes(body).decode("utf-8", "replace")
                    mid = ""
                    for line in text.splitlines():
                        if line.lower().startswith("message-id:"):
                            mid = line.split(":", 1)[1].strip()
                            break
                    out[cur_uid] = mid
                    cur_uid = None
        return out

    def append(self, folder: str, raw: bytes, flags: list[str] | None = None,
               internaldate: str | None = None) -> None:
        flag_str = " ".join(f for f in (flags or []) if not f.startswith("\\Recent"))
        if internaldate and not (internaldate.startswith('"') and internaldate.endswith('"')):
            internaldate = f'"{internaldate}"'
        typ, data = self.conn.append(
            _imap_quote(folder),
            f"({flag_str})" if flag_str else None,
            internaldate,
            raw,
        )
        if typ != "OK":
            raise ImapError(f"APPEND to {folder!r} failed: {data!r}")

    def expunge_all(self, folder: str) -> int:
        """Mark every message in folder \\Deleted then EXPUNGE. Returns count."""
        typ, data = self.conn.select(_imap_quote(folder), readonly=False)
        if typ != "OK":
            raise ImapError(f"SELECT {folder!r} failed: {data!r}")
        try:
            count = int(data[0])
        except (ValueError, IndexError):
            count = 0
        if count == 0:
            return 0
        typ, _ = self.conn.uid("STORE", "1:*", "+FLAGS.SILENT", "(\\Deleted)")
        if typ != "OK":
            raise ImapError("STORE +FLAGS \\Deleted failed")
        typ, _ = self.conn.expunge()
        if typ != "OK":
            raise ImapError("EXPUNGE failed")
        return count


# ---------------------------------------------------------------------------
# Folder auto-pairing (RFC 6154)
# ---------------------------------------------------------------------------

def auto_pair_folders(
    old_folders: list[FolderInfo], new_folders: list[FolderInfo]
) -> list[dict]:
    """Return [{old, new, action, pairing_reason, special_use}, ...].

    Rule order:
      1. identical name (case-insensitive)
      2. matching SPECIAL-USE flag
      3. unmatched -> action=skip, operator must choose
    """
    new_by_lower = {nf.name.lower(): nf for nf in new_folders}
    new_by_special = {nf.special_use: nf for nf in new_folders if nf.special_use}

    rows: list[dict] = []
    for of in old_folders:
        # rule 1
        nf = new_by_lower.get(of.name.lower())
        if nf is not None:
            rows.append({
                "old": of.name,
                "new": nf.name,
                "action": "map",
                "pairing_reason": "name",
                "special_use": of.special_use,
            })
            continue
        # rule 2
        if of.special_use and of.special_use in new_by_special:
            nf = new_by_special[of.special_use]
            rows.append({
                "old": of.name,
                "new": nf.name,
                "action": "map",
                "pairing_reason": "special-use",
                "special_use": of.special_use,
            })
            continue
        # rule 3
        rows.append({
            "old": of.name,
            "new": "",
            "action": "skip",
            "pairing_reason": "",
            "special_use": of.special_use,
        })
    return rows


def parse_message_id(raw: bytes) -> str:
    """Extract Message-ID from raw RFC822, normalised. Empty if absent."""
    head_end = raw.find(b"\r\n\r\n")
    if head_end == -1:
        head_end = raw.find(b"\n\n")
    head = raw[:head_end].decode("utf-8", "replace") if head_end != -1 else raw.decode("utf-8", "replace")
    for line in head.splitlines():
        if line.lower().startswith("message-id:"):
            value = line.split(":", 1)[1].strip()
            return value
    return ""


def synthetic_message_id(raw: bytes) -> str:
    """Stable sha-based fallback id for messages without a Message-ID header."""
    import hashlib
    return f"<sha256-{hashlib.sha256(raw).hexdigest()}@local>"
