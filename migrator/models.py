from django.conf import settings
from django.db import models
from django.utils import timezone


class Migration(models.Model):
    """One migration session: source mailbox -> destination mailbox."""

    owner = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="migrations",
        null=True, blank=True,
    )
    name = models.CharField(max_length=200, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    old_host = models.CharField(max_length=255)
    old_port = models.PositiveIntegerField(default=993)
    old_username = models.CharField(max_length=255)
    old_use_ssl = models.BooleanField(default=True)

    new_host = models.CharField(max_length=255)
    new_port = models.PositiveIntegerField(default=993)
    new_username = models.CharField(max_length=255)
    new_use_ssl = models.BooleanField(default=True)

    old_password_enc = models.BinaryField(blank=True, default=b"")
    new_password_enc = models.BinaryField(blank=True, default=b"")

    def __str__(self) -> str:
        label = self.name or f"{self.old_username} -> {self.new_username}"
        return f"Migration #{self.pk} ({label})"


class FolderMapping(models.Model):
    """Pairs an old-server folder with a new-server folder."""

    ACTION_MAP = "map"
    ACTION_CREATE = "create"
    ACTION_SKIP = "skip"
    ACTION_CHOICES = [
        (ACTION_MAP, "Map to existing folder"),
        (ACTION_CREATE, "Create on new server"),
        (ACTION_SKIP, "Skip"),
    ]

    PAIRING_NAME = "name"
    PAIRING_SPECIAL_USE = "special-use"
    PAIRING_MANUAL = "manual"
    PAIRING_NONE = ""

    migration = models.ForeignKey(
        Migration, on_delete=models.CASCADE, related_name="folder_mappings"
    )
    old_folder = models.CharField(max_length=500)
    new_folder = models.CharField(max_length=500, blank=True)
    action = models.CharField(max_length=10, choices=ACTION_CHOICES, default=ACTION_MAP)
    pairing_reason = models.CharField(max_length=20, blank=True)
    special_use = models.CharField(max_length=20, blank=True)

    class Meta:
        unique_together = [("migration", "old_folder")]

    def __str__(self) -> str:
        return f"{self.old_folder} -> {self.new_folder or '(skip)'}"


class PhaseRun(models.Model):
    """One execution of one phase (Backup, Transfer, Verify, Cleanup)."""

    PHASE_BACKUP = "backup"
    PHASE_TRANSFER = "transfer"
    PHASE_VERIFY = "verify"
    PHASE_CLEANUP = "cleanup"
    PHASE_CHOICES = [
        (PHASE_BACKUP, "Backup"),
        (PHASE_TRANSFER, "Transfer"),
        (PHASE_VERIFY, "Verify"),
        (PHASE_CLEANUP, "Cleanup"),
    ]

    STATUS_PENDING = "pending"
    STATUS_RUNNING = "running"
    STATUS_SUCCESS = "success"
    STATUS_FAILED = "failed"
    STATUS_CHOICES = [
        (STATUS_PENDING, "Pending"),
        (STATUS_RUNNING, "Running"),
        (STATUS_SUCCESS, "Success"),
        (STATUS_FAILED, "Failed"),
    ]

    migration = models.ForeignKey(
        Migration, on_delete=models.CASCADE, related_name="phase_runs"
    )
    phase = models.CharField(max_length=20, choices=PHASE_CHOICES)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default=STATUS_PENDING)
    started_at = models.DateTimeField(null=True, blank=True)
    finished_at = models.DateTimeField(null=True, blank=True)
    processed = models.PositiveIntegerField(default=0)
    total = models.PositiveIntegerField(default=0)
    error = models.TextField(blank=True)
    log_path = models.CharField(max_length=500, blank=True)

    class Meta:
        ordering = ["-started_at", "-id"]


class MessageRecord(models.Model):
    """Per-message ledger keyed by Message-ID for deduplication and DB-backed backup."""

    migration = models.ForeignKey(
        Migration, on_delete=models.CASCADE, related_name="messages"
    )
    folder = models.CharField(max_length=500)
    message_id = models.CharField(max_length=500)
    backed_up = models.BooleanField(default=False)
    transferred = models.BooleanField(default=False)
    verified = models.BooleanField(default=False)
    size = models.PositiveIntegerField(default=0)

    raw_bytes = models.BinaryField(blank=True, default=b"")
    flags = models.TextField(blank=True)
    internaldate = models.CharField(max_length=64, blank=True)
    source_uid = models.PositiveIntegerField(default=0)

    class Meta:
        unique_together = [("migration", "folder", "message_id")]
        indexes = [
            models.Index(fields=["migration", "folder"]),
            models.Index(fields=["migration", "message_id"]),
        ]


class UserProfile(models.Model):
    """Per-user preferences. Auto-created on first access via get_or_create."""

    user = models.OneToOneField(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="profile",
    )
    notifications_enabled = models.BooleanField(default=False)
    # Empty means "use the account's primary email address".
    notify_email = models.EmailField(blank=True)

    def __str__(self) -> str:
        return f"Profile<{self.user_id}>"

    def resolved_email(self) -> str:
        return (self.notify_email or self.user.email or "").strip()


class AccessEvent(models.Model):
    """Admin-only activity feed: who opened an auth page or created an account.

    Populated by AccessLogMiddleware (page visits) and the signup adapter
    (account creations). Surfaced on the admin Notifications page. `seen`
    drives the unread badge in the nav.
    """

    KIND_VISIT = "visit"
    KIND_SIGNUP = "signup"
    KIND_CHOICES = [
        (KIND_VISIT, "Page visit"),
        (KIND_SIGNUP, "Account signup"),
    ]

    kind = models.CharField(max_length=20, choices=KIND_CHOICES, default=KIND_VISIT)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    path = models.CharField(max_length=300, blank=True)
    # For signup events: the email address that was submitted.
    email = models.CharField(max_length=254, blank=True)
    user_agent = models.CharField(max_length=400, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)   # first seen
    last_seen = models.DateTimeField(default=timezone.now)  # bumped on repeat visits
    hits = models.PositiveIntegerField(default=1)           # times this row was hit
    seen = models.BooleanField(default=False)

    class Meta:
        ordering = ["-last_seen", "-id"]
        indexes = [
            models.Index(fields=["-last_seen"]),
            models.Index(fields=["seen"]),
            models.Index(fields=["kind"]),
        ]

    def __str__(self) -> str:
        return f"{self.get_kind_display()} from {self.ip_address or '?'} @ {self.last_seen:%Y-%m-%d %H:%M}"


class VerificationReport(models.Model):
    """Result of a Verify phase run; consulted by Cleanup safety checks."""

    migration = models.OneToOneField(
        Migration, on_delete=models.CASCADE, related_name="verification"
    )
    created_at = models.DateTimeField(auto_now=True)
    total_old = models.PositiveIntegerField(default=0)
    total_new = models.PositiveIntegerField(default=0)
    missing_total = models.PositiveIntegerField(default=0)
    folders_json = models.JSONField(default=dict)

    @property
    def all_green(self) -> bool:
        return self.missing_total == 0 and bool(self.folders_json)
