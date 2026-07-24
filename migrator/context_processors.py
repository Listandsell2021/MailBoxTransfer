from django.conf import settings


def turnstile(request):
    """Expose the Cloudflare Turnstile site key to every template.

    Empty when unconfigured (local/dev) so the signup template can skip
    rendering the widget entirely.
    """
    return {"TURNSTILE_SITE_KEY": getattr(settings, "TURNSTILE_SITE_KEY", "")}
