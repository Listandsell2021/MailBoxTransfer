from django import forms

from allauth.account.forms import SignupForm

from .models import Migration, UserProfile


class MailboxSignupForm(SignupForm):
    """Adds first/last name to allauth's default email + password signup form."""

    first_name = forms.CharField(
        max_length=150, required=True,
        widget=forms.TextInput(attrs={"autocomplete": "given-name"}),
    )
    last_name = forms.CharField(
        max_length=150, required=True,
        widget=forms.TextInput(attrs={"autocomplete": "family-name"}),
    )

    field_order = ["first_name", "last_name", "email", "password1", "password2"]

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
