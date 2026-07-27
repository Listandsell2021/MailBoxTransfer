from django.conf import settings
from django.core.mail import mail_admins
from django.urls import reverse

from allauth.account.adapter import DefaultAccountAdapter
from allauth.socialaccount.adapter import DefaultSocialAccountAdapter


class MailboxAccountAdapter(DefaultAccountAdapter):
    """Local-signup adapter for the Mailbox Transfer app.

    Approval-gated, no signup mail. State machine:
      1. Signup      → user created is_active=False. NO email is sent (that's the
                       whole point — we never mail bot/harvested addresses). The
                       admin is notified in-app (Notifications) + by mail_admins.
                       allauth shows the "awaiting approval" page.
      2. Admin ticks → admin clicks Activate on the Users page → is_active=True,
                       and a single "you're approved" email goes to the user
                       (see views.toggle_user_active). Login now succeeds and the
                       user proceeds to TOTP setup.
    """

    def is_open_for_signup(self, request):
        return True

    def format_email_subject(self, subject):
        # allauth's default prepends "[<site_name>] " to every subject. The
        # default Site row has name="example.com" / domain="localhost", which
        # would render as "[localhost] Verify ..." in users' inboxes. Skip the
        # prefix entirely — our subjects already include the product name.
        return str(subject).strip()

    def save_user(self, request, user, form, commit=True):
        # Create the account INACTIVE (pending admin approval) and persist
        # first/last name. No verification email is sent — the account can't log
        # in until an admin approves it, and only then do we email the user.
        user = super().save_user(request, user, form, commit=False)
        user.first_name = (form.cleaned_data.get("first_name") or "").strip()
        user.last_name = (form.cleaned_data.get("last_name") or "").strip()
        user.is_active = False
        if commit:
            user.save()
            self._log_signup_event(request, user)
            self._mail_admins_about_signup(user, user.email)
        return user

    def _log_signup_event(self, request, user):
        # Record the account-creation attempt in the admin Notifications feed.
        # Never let a logging hiccup break the signup itself.
        from .middleware import get_client_ip
        from .models import AccessEvent
        try:
            user_agent = request.META.get("HTTP_USER_AGENT", "") if request else ""
            AccessEvent.objects.create(
                kind=AccessEvent.KIND_SIGNUP,
                ip_address=get_client_ip(request) if request else None,
                path=getattr(request, "path", "") or "",
                email=(user.email or "")[:254],
                user_agent=(user_agent or "")[:400],
            )
        except Exception:
            pass

    def _mail_admins_about_signup(self, user, email):
        if not settings.ADMINS:
            return
        label = f"{user.first_name} {user.last_name}".strip() or email
        try:
            users_url = reverse("migrator:users")
        except Exception:
            users_url = "/users/"
        mail_admins(
            subject=f"[Mailbox Transfer] New signup awaiting approval: {label}",
            message=(
                f"A new account has signed up and is waiting for your approval.\n\n"
                f"Name:  {label}\n"
                f"Email: {email}\n\n"
                f"Review and activate them from the Users page (click 'Activate' on their row):\n"
                f"  {users_url}\n"
            ),
            fail_silently=True,
        )


class GoogleOnlySocialAdapter(DefaultSocialAccountAdapter):
    """Allow signup via social account regardless of the local-signup setting.

    The default social adapter delegates is_open_for_signup to the account
    adapter; we want Google signups to remain frictionless even if local signup
    is ever closed off again.
    """

    def is_open_for_signup(self, request, sociallogin):
        return True
