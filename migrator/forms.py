from django import forms
from django.utils import timezone

from allauth.account.forms import SignupForm

from .models import BackupJob, Migration, RestoreJob, UserProfile


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


class BackupJobForm(forms.ModelForm):
    """Source mailbox only — a backup job has no destination server."""

    password = forms.CharField(
        widget=forms.PasswordInput(
            render_value=False,
            attrs={"placeholder": "(leave blank to keep current)"},
        ),
        required=False,
    )
    security = forms.ChoiceField(choices=SECURITY_CHOICES, required=True, initial="ssl")

    class Meta:
        model = BackupJob
        fields = ["name", "host", "port", "username"]
        labels = {"name": "Label", "username": "Email / username"}

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        if self.instance and self.instance.pk:
            self.fields["security"].initial = "ssl" if self.instance.use_ssl else "none"
        else:
            # A brand-new job has nothing stored to fall back on.
            self.fields["password"].required = True
            self.fields["password"].widget.attrs["placeholder"] = "Mailbox password"

    def clean_password(self):
        pwd = self.cleaned_data.get("password") or ""
        if not pwd and not (self.instance and self.instance.pk):
            raise forms.ValidationError("Enter the mailbox password.")
        return pwd

    def save(self, commit: bool = True):
        obj = super().save(commit=False)
        obj.use_ssl = self.cleaned_data["security"] == "ssl"
        if commit:
            obj.save()
        return obj


class BackupScheduleForm(forms.ModelForm):
    """How often a backup job runs by itself. Times are in the project
    timezone (Europe/Berlin), which is what the user sees on the page."""

    HOUR_CHOICES = [(h, f"{h:02d}") for h in range(24)]
    MINUTE_CHOICES = [(m, f"{m:02d}") for m in (0, 15, 30, 45)]

    schedule_hour = forms.TypedChoiceField(
        choices=HOUR_CHOICES, coerce=int, label="Hour",
    )
    schedule_minute = forms.TypedChoiceField(
        choices=MINUTE_CHOICES, coerce=int, label="Minute",
    )
    schedule_weekday = forms.TypedChoiceField(
        choices=BackupJob.WEEKDAY_CHOICES, coerce=int, label="Day",
    )

    class Meta:
        model = BackupJob
        fields = ["schedule", "schedule_hour", "schedule_minute", "schedule_weekday"]
        labels = {"schedule": "Run automatically"}

    def clean(self):
        cleaned = super().clean()
        # "Every hour" means a full hour from when you saved it: a schedule
        # saved at 11:27 runs 12:27, 13:27, … So anchor the minute to the save
        # time rather than trusting whatever the hidden minute field held.
        # 6-hourly keeps its fixed 00/06/12/18 slots.
        if cleaned.get("schedule") == BackupJob.SCHEDULE_HOURLY:
            cleaned["schedule_minute"] = timezone.localtime().minute
        elif cleaned.get("schedule") == BackupJob.SCHEDULE_6H:
            cleaned["schedule_minute"] = 0
        return cleaned


class RestoreJobForm(forms.ModelForm):
    """Destination mailbox for an import, plus where the messages come from."""

    password = forms.CharField(
        widget=forms.PasswordInput(
            render_value=False,
            attrs={"placeholder": "(leave blank to keep current)"},
        ),
        required=False,
    )
    security = forms.ChoiceField(choices=SECURITY_CHOICES, required=True, initial="ssl")
    archive = forms.FileField(
        required=False,
        help_text="A backup ZIP, a .zip of .eml/.mbox files, or a single .eml/.mbox.",
    )

    class Meta:
        model = RestoreJob
        fields = ["name", "host", "port", "username", "source_kind", "source_backup"]
        labels = {
            "name": "Label",
            "username": "Email / username",
            "source_kind": "Import from",
            "source_backup": "Backup",
        }

    def __init__(self, *args, user=None, backups=None, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields["source_backup"].required = False
        # The caller passes the scope explicitly so an admin can import from
        # anyone's backup; `user` stays the fallback for plain callers.
        if backups is None:
            backups = (
                BackupJob.objects.filter(owner=user) if user
                else BackupJob.objects.none()
            )
        self.fields["source_backup"].queryset = backups
        self.fields["source_backup"].empty_label = "— choose a backup —"
        if self.instance and self.instance.pk:
            self.fields["security"].initial = "ssl" if self.instance.use_ssl else "none"
        else:
            self.fields["password"].required = True
            self.fields["password"].widget.attrs["placeholder"] = "Mailbox password"

    def clean(self):
        cleaned = super().clean()
        kind = cleaned.get("source_kind")
        editing = bool(self.instance and self.instance.pk)

        if kind == RestoreJob.SOURCE_BACKUP:
            if not cleaned.get("source_backup"):
                self.add_error("source_backup", "Pick which backup to import.")
        else:
            cleaned["source_backup"] = None
            # On edit, an archive is already ingested; only require one up front.
            if not cleaned.get("archive") and not editing:
                self.add_error("archive", "Choose an archive file to upload.")
        return cleaned

    def clean_password(self):
        pwd = self.cleaned_data.get("password") or ""
        if not pwd and not (self.instance and self.instance.pk):
            raise forms.ValidationError("Enter the destination mailbox password.")
        return pwd

    def save(self, commit: bool = True):
        obj = super().save(commit=False)
        obj.use_ssl = self.cleaned_data["security"] == "ssl"
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
            "notifications_enabled":
                "Email me when a migration phase, a mailbox backup or an import finishes",
        }
