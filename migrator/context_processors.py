from django.conf import settings
from django.db import DatabaseError


def turnstile(request):
    """Expose the Cloudflare Turnstile site key to every template.

    Empty when unconfigured (local/dev) so the signup template can skip
    rendering the widget entirely.
    """
    return {"TURNSTILE_SITE_KEY": getattr(settings, "TURNSTILE_SITE_KEY", "")}


def notifications_badge(request):
    """Unread AccessEvent count for the nav badge (admins only)."""
    user = getattr(request, "user", None)
    if not (user and user.is_authenticated and (user.is_superuser or user.is_staff)):
        return {"unseen_notifications": 0}
    try:
        from .models import AccessEvent
        count = AccessEvent.objects.filter(seen=False).count()
    except DatabaseError:
        count = 0
    return {"unseen_notifications": count}
