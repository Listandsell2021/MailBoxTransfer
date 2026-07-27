"""Cloudflare Turnstile server-side verification, shared by the signup form and
the login view.

Fail-safe design: when no secret key is configured (local/dev), enforcement is
off and pages skip the widget entirely, so auth still works without Cloudflare.
"""
from __future__ import annotations

import json
from urllib import parse as urllib_parse, request as urllib_request
from urllib.error import URLError

from django.conf import settings

VERIFY_URL = "https://challenges.cloudflare.com/turnstile/v0/siteverify"


def enforced() -> bool:
    """True when a secret key is set, i.e. the CAPTCHA should be enforced."""
    return bool(getattr(settings, "TURNSTILE_SECRET_KEY", ""))


def verify_token(token: str | None) -> bool:
    """Validate a Turnstile response token against Cloudflare's siteverify API.

    Returns True when the token is valid (or Turnstile isn't configured), and
    False when the token is missing, invalid, or couldn't be verified. Callers
    that enforce should first check enforced() so they can show a precise
    'please complete the CAPTCHA' message for the empty-token case.
    """
    secret = getattr(settings, "TURNSTILE_SECRET_KEY", "")
    if not secret:
        return True
    token = (token or "").strip()
    if not token:
        return False
    payload = urllib_parse.urlencode({"secret": secret, "response": token}).encode()
    try:
        req = urllib_request.Request(VERIFY_URL, data=payload)
        with urllib_request.urlopen(req, timeout=10) as resp:
            result = json.loads(resp.read().decode())
    except (URLError, ValueError, OSError):
        return False
    return bool(result.get("success"))
