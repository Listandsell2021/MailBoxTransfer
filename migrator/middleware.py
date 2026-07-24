"""Admin activity logging — records visits to the auth pages.

Only the signup and login pages are logged (see WATCHED_PATHS), and repeat
hits from the same IP+path inside DEDUP_WINDOW are collapsed into the first
one, so bots probing the login page don't flood the Notifications feed.
Account-creation events are logged separately by the signup adapter.
"""
from __future__ import annotations

from datetime import timedelta

from django.db import DatabaseError
from django.utils import timezone

# Paths whose GET requests count as a "visit". Kept deliberately small.
WATCHED_PATHS = ("/accounts/signup/", "/login/")

# Don't record the same IP hitting the same page more than once per window.
DEDUP_WINDOW = timedelta(minutes=15)


def get_client_ip(request) -> str | None:
    """Best-effort real client IP behind Cloudflare / nginx.

    Order: Cloudflare's CF-Connecting-IP, then the first hop of
    X-Forwarded-For, then the raw socket address.
    """
    cf = request.META.get("HTTP_CF_CONNECTING_IP")
    if cf:
        return cf.strip()
    xff = request.META.get("HTTP_X_FORWARDED_FOR")
    if xff:
        # "client, proxy1, proxy2" — the client is the first entry.
        return xff.split(",")[0].strip()
    return request.META.get("REMOTE_ADDR")


class AccessLogMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        try:
            self._maybe_log(request)
        except DatabaseError:
            # Never let logging break the actual request (e.g. before migrate).
            pass
        return self.get_response(request)

    def _maybe_log(self, request):
        if request.method != "GET":
            return
        path = request.path
        if path not in WATCHED_PATHS:
            return

        # Import here so the app registry is ready when middleware is built.
        from django.db.models import F

        from .models import AccessEvent

        ip = get_client_ip(request)
        now = timezone.now()
        cutoff = now - DEDUP_WINDOW

        # A visit within the window bumps the existing row's hit count and
        # last-seen time instead of creating a new one. Outside the window it
        # starts a fresh row (a new "session").
        existing = (
            AccessEvent.objects.filter(
                kind=AccessEvent.KIND_VISIT,
                path=path,
                ip_address=ip,
                last_seen__gte=cutoff,
            )
            .order_by("-last_seen")
            .first()
        )
        if existing:
            AccessEvent.objects.filter(pk=existing.pk).update(
                hits=F("hits") + 1, last_seen=now, seen=False,
            )
            return

        AccessEvent.objects.create(
            kind=AccessEvent.KIND_VISIT,
            ip_address=ip,
            path=path,
            user_agent=(request.META.get("HTTP_USER_AGENT", "") or "")[:400],
            last_seen=now,
        )
