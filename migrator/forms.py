from django import forms

from allauth.account.forms import SignupForm

from .models import Migration, UserProfile


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
        self._verify_email_domain(cleaned.get("email"))
        return cleaned

    def _verify_email_domain(self, email):
        # Reject signups whose email domain can't receive mail, so we never
        # send a verification email to a dead/fake domain (the bounce source).
        # Fail open: only block on a definitive "domain doesn't exist".
        from .email_validation import domain_can_receive_mail, email_domain
        domain = email_domain(email or "")
        if not domain:
            return
        if domain_can_receive_mail(domain) is False:
            self.add_error(
                "email",
                forms.ValidationError(
                    "That email domain can't receive mail. Please check the address."
                ),
            )

    def _verify_turnstile(self):
        from .turnstile import enforced, verify_token
        if not enforced():
            # Unconfigured (local/dev): no CAPTCHA to enforce.
            return
        token = (self.data.get("cf-turnstile-response") or "").strip()
        if not token:
            raise forms.ValidationError("Please complete the CAPTCHA to continue.")
        if not verify_token(token):
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
