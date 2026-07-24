import json
from urllib import parse as urllib_parse, request as urllib_request
from urllib.error import URLError

from django import forms
from django.conf import settings

from allauth.account.forms import SignupForm

from .models import Migration, UserProfile

TURNSTILE_VERIFY_URL = "https://challenges.cloudflare.com/turnstile/v0/siteverify"


class MailboxSignupForm(SignupForm):
    """Adds first/last name to allauth's default email + password signup form.

    Also enforces a Cloudflare Turnstile CAPTCHA server-side to keep bots from
    mass-creating unverified accounts (which then bounce our verification mail
    and wreck sender reputation). The token is posted by the widget rendered in
    signup.html under the field name 'cf-turnstile-response'.
    """

    first_name = forms.CharField(
        max_length=150, required=True,
        widget=forms.TextInput(attrs={"autocomplete": "given-name"}),
    )
    last_name = forms.CharField(
        max_length=150, required=True,
        widget=forms.TextInput(attrs={"autocomplete": "family-name"}),
    )

    field_order = ["first_name", "last_name", "email", "password1", "password2"]

    def clean(self):
        cleaned = super().clean()
        self._verify_turnstile()
        return cleaned

    def _verify_turnstile(self):
        secret = getattr(settings, "TURNSTILE_SECRET_KEY", "")
        if not secret:
            # Unconfigured (local/dev): no CAPTCHA to enforce.
            return
        token = (self.data.get("cf-turnstile-response") or "").strip()
        if not token:
            raise forms.ValidationError("Please complete the CAPTCHA to continue.")
        payload = urllib_parse.urlencode({"secret": secret, "response": token}).encode()
        try:
            req = urllib_request.Request(TURNSTILE_VERIFY_URL, data=payload)
            with urllib_request.urlopen(req, timeout=10) as resp:
                result = json.loads(resp.read().decode())
        except (URLError, ValueError, OSError):
            raise forms.ValidationError(
                "Could not verify the CAPTCHA right now. Please try again."
            )
        if not result.get("success"):
            raise forms.ValidationError("CAPTCHA verification failed. Please try again.")

    def save(self, request):
        # allauth's SignupForm.save() instantiates the user and then calls the
        # account adapter's save_user(); the adapter persists first/last name.
        return super().save(request)


SECURITY_CHOICES = [("ssl", "SSL/TLS"), ("none", "None (plain)")]


class MigrationForm(forms.ModelForm):
    old_password = forms.CharField(
        widget=forms.PasswordInput(render_value=False, attrs={"placeholder": "(leave blank to keep current)"}),
        required=False,
    )
    new_password = forms.CharField(
        widget=forms.PasswordInput(render_value=False, attrs={"placeholder": "(leave blank to keep current)"}),
        required=False,
    )
    old_security = forms.ChoiceField(choices=SECURITY_CHOICES, required=True, initial="ssl")
    new_security = forms.ChoiceField(choices=SECURITY_CHOICES, required=True, initial="ssl")

    class Meta:
        model = Migration
        fields = [
            "name",
            "old_host", "old_port", "old_username",
            "new_host", "new_port", "new_username",
        ]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        if self.instance and self.instance.pk:
            self.fields["old_security"].initial = "ssl" if self.instance.old_use_ssl else "none"
            self.fields["new_security"].initial = "ssl" if self.instance.new_use_ssl else "none"

    def save(self, commit: bool = True):
        obj = super().save(commit=False)
        obj.old_use_ssl = self.cleaned_data["old_security"] == "ssl"
        obj.new_use_ssl = self.cleaned_data["new_security"] == "ssl"
        if commit:
            obj.save()
        return obj


class ProfileForm(forms.ModelForm):
    notify_email = forms.EmailField(
        required=False,
        widget=forms.EmailInput(attrs={"placeholder": "(leave blank to use account email)"}),
        help_text="Leave blank to send notifications to your account email.",
    )

    class Meta:
        model = UserProfile
        fields = ["notifications_enabled", "notify_email"]
        labels = {
            "notifications_enabled": "Send me email notifications when a migration phase finishes",
        }
