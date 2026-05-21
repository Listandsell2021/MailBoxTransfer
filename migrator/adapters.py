from django.conf import settings
from django.core.mail import mail_admins
from django.urls import reverse

from allauth.account.adapter import DefaultAccountAdapter
from allauth.socialaccount.adapter import DefaultSocialAccountAdapter


class MailboxAccountAdapter(DefaultAccountAdapter):
    """Local-signup adapter for the Mailbox Transfer app.

    State machine:
      1. Signup       → user is created active-but-unverified. Verification email
                        goes out. allauth's mandatory-verification gate blocks
                        login during this window even though is_active is True.
      2. Email verified → confirm_email() flips is_active to False so the user
                          still can't log in. mail_admins() nudges the admin.
      3. Admin ticks    → admin sets is_active=True in /admin/auth/user/. Login
         'is active'      now succeeds and the user proceeds to TOTP setup.
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
        # Persist first/last name from the signup form; leave is_active=True so
        # the verification email actually goes out (allauth skips emailing
        # inactive users — they can't log in anyway).
        user = super().save_user(request, user, form, commit=False)
        user.first_name = (form.cleaned_data.get("first_name") or "").strip()
        user.last_name = (form.cleaned_data.get("last_name") or "").strip()
        if commit:
            user.save()
        return user

    def confirm_email(self, request, email_address):
        # Email verified → switch to "awaiting admin approval" and notify the admin.
        super().confirm_email(request, email_address)
        user = email_address.user
        if user.is_active:
            user.is_active = False
            user.save(update_fields=["is_active"])
        self._mail_admins_about_signup(user, email_address.email)

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
                f"A user has verified their email and is now waiting for activation.\n\n"
                f"Name:  {label}\n"
                f"Email: {email}\n\n"
                f"Activate them from the Users page (click 'Activate' on their row):\n"
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
