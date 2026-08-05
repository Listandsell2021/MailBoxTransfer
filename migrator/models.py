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


class BackupJob(models.Model):
    """A standalone, backup-only mailbox archive.

    Unlike `Migration`, this has no destination server and never writes to a
    mail server: it only downloads every selected folder from one IMAP account
    into the database, attachments and all, so the owner can pull the whole
    mailbox down as a ZIP. Available to every signed-in user; a job is visible
    only to the user who created it.
    """

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

    owner = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="backup_jobs",
    )
    name = models.CharField(max_length=200, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    host = models.CharField(max_length=255)
    port = models.PositiveIntegerField(default=993)
    username = models.CharField(max_length=255)
    use_ssl = models.BooleanField(default=True)
    password_enc = models.BinaryField(blank=True, default=b"")

    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default=STATUS_PENDING)
    started_at = models.DateTimeField(null=True, blank=True)
    finished_at = models.DateTimeField(null=True, blank=True)
    processed = models.PositiveIntegerField(default=0)
    total = models.PositiveIntegerField(default=0)
    error = models.TextField(blank=True)
    folders_listed_at = models.DateTimeField(null=True, blank=True)

    # -- schedule ----------------------------------------------------------
    # Times are interpreted in the project timezone (settings.TIME_ZONE), which
    # is what a user picking "03:00" means. `next_run_at` is stored UTC like
    # every other datetime and is what the scheduler actually queries on.
    SCHEDULE_OFF = "off"
    SCHEDULE_HOURLY = "hourly"
    SCHEDULE_6H = "6h"
    SCHEDULE_DAILY = "daily"
    SCHEDULE_WEEKLY = "weekly"
    SCHEDULE_CHOICES = [
        (SCHEDULE_OFF, "Off — run manually"),
        (SCHEDULE_HOURLY, "Every hour"),
        (SCHEDULE_6H, "Every 6 hours"),
        (SCHEDULE_DAILY, "Every day"),
        (SCHEDULE_WEEKLY, "Every week"),
    ]
    WEEKDAY_CHOICES = [
        (0, "Monday"), (1, "Tuesday"), (2, "Wednesday"), (3, "Thursday"),
        (4, "Friday"), (5, "Saturday"), (6, "Sunday"),
    ]

    schedule = models.CharField(
        max_length=10, choices=SCHEDULE_CHOICES, default=SCHEDULE_OFF,
    )
    schedule_hour = models.PositiveSmallIntegerField(default=3)
    schedule_minute = models.PositiveSmallIntegerField(default=0)
    schedule_weekday = models.PositiveSmallIntegerField(
        choices=WEEKDAY_CHOICES, default=0,
    )
    next_run_at = models.DateTimeField(null=True, blank=True, db_index=True)
    last_scheduled_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ["-created_at", "-id"]

    def __str__(self) -> str:
        return f"BackupJob #{self.pk} ({self.label})"

    @property
    def label(self) -> str:
        return self.name or self.username or f"backup-{self.pk}"

    @property
    def schedule_is_on(self) -> bool:
        return self.schedule != self.SCHEDULE_OFF

    def schedule_description(self) -> str:
        """Human phrasing of the schedule, for the UI."""
        hhmm = f"{self.schedule_hour:02d}:{self.schedule_minute:02d}"
        if self.schedule == self.SCHEDULE_OFF:
            return "Manual only"
        if self.schedule == self.SCHEDULE_HOURLY:
            # The minute is the one the schedule was saved at, so an hourly job
            # set up at 11:27 reads "Every hour at :27" and runs 12:27, 13:27…
            return f"Every hour at :{self.schedule_minute:02d}"
        if self.schedule == self.SCHEDULE_6H:
            return "Every 6 hours (00:00, 06:00, 12:00, 18:00)"
        if self.schedule == self.SCHEDULE_DAILY:
            return f"Daily at {hhmm}"
        day = dict(self.WEEKDAY_CHOICES).get(self.schedule_weekday, "Monday")
        return f"Every {day} at {hhmm}"


class RestoreJob(models.Model):
    """Import archived messages into a mailbox — the reverse of a BackupJob.

    The source is either an archive the user uploaded (a ZIP produced by the
    Download ZIP button, a ZIP of .eml/.mbox files, or a single .eml/.mbox) or
    a BackupJob already stored in the app. Messages are only ever APPENDed to
    the destination; nothing on either server is deleted.
    """

    SOURCE_UPLOAD = "upload"
    SOURCE_BACKUP = "backup"
    SOURCE_CHOICES = [
        (SOURCE_UPLOAD, "Uploaded archive"),
        (SOURCE_BACKUP, "Existing backup in this app"),
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

    owner = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="restore_jobs",
    )
    name = models.CharField(max_length=200, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    # Destination mailbox — the only server this job talks to.
    host = models.CharField(max_length=255)
    port = models.PositiveIntegerField(default=993)
    username = models.CharField(max_length=255)
    use_ssl = models.BooleanField(default=True)
    password_enc = models.BinaryField(blank=True, default=b"")

    source_kind = models.CharField(
        max_length=10, choices=SOURCE_CHOICES, default=SOURCE_UPLOAD,
    )
    # Kept as SET_NULL: deleting the backup shouldn't erase the record of an
    # import that already happened.
    source_backup = models.ForeignKey(
        "BackupJob", on_delete=models.SET_NULL,
        null=True, blank=True, related_name="restores",
    )
    archive_name = models.CharField(max_length=255, blank=True)
    archive_size = models.PositiveBigIntegerField(default=0)

    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default=STATUS_PENDING)
    started_at = models.DateTimeField(null=True, blank=True)
    finished_at = models.DateTimeField(null=True, blank=True)
    processed = models.PositiveIntegerField(default=0)
    total = models.PositiveIntegerField(default=0)
    imported = models.PositiveIntegerField(default=0)
    skipped = models.PositiveIntegerField(default=0)
    failed = models.PositiveIntegerField(default=0)
    error = models.TextField(blank=True)
    paired_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ["-created_at", "-id"]

    def __str__(self) -> str:
        return f"RestoreJob #{self.pk} ({self.label})"

    @property
    def label(self) -> str:
        return self.name or self.username or f"restore-{self.pk}"

    @property
    def source_label(self) -> str:
        if self.source_kind == self.SOURCE_UPLOAD:
            return self.archive_name or "uploaded archive"
        return self.source_backup.label if self.source_backup else "(backup deleted)"


class RestoreFolder(models.Model):
    """One folder found in the archive, and where it should land."""

    ACTION_MAP = "map"
    ACTION_CREATE = "create"
    ACTION_SKIP = "skip"
    ACTION_CHOICES = [
        (ACTION_MAP, "Import into existing folder"),
        (ACTION_CREATE, "Create on destination"),
        (ACTION_SKIP, "Skip"),
    ]

    job = models.ForeignKey(RestoreJob, on_delete=models.CASCADE, related_name="folders")
    source_folder = models.CharField(max_length=500)
    # The separator INSIDE source_folder, which differs by where it came from:
    # "/" for a ZIP path, but the source server's own delimiter (often ".") when
    # restoring from a backup stored in this app, where the raw IMAP name is
    # kept so the messages can still be looked up. Splitting on the wrong one
    # turns "INBOX.Berlin" into a single flat folder called "INBOX.Berlin".
    source_delimiter = models.CharField(max_length=4, default="/")
    dest_folder = models.CharField(max_length=500, blank=True)
    action = models.CharField(max_length=10, choices=ACTION_CHOICES, default=ACTION_MAP)
    pairing_reason = models.CharField(max_length=20, blank=True)
    message_count = models.PositiveIntegerField(default=0)
    imported = models.PositiveIntegerField(default=0)

    class Meta:
        unique_together = [("job", "source_folder")]
        ordering = ["source_folder"]

    def __str__(self) -> str:
        return f"{self.source_folder} -> {self.dest_folder or '(skip)'}"


class RestoreMessage(models.Model):
    """A message parsed out of an uploaded archive, waiting to be imported.

    Only used for `source_kind == upload`; a restore from an existing BackupJob
    reads BackupMessage rows directly instead of copying every message.
    """

    job = models.ForeignKey(RestoreJob, on_delete=models.CASCADE, related_name="messages")
    folder = models.CharField(max_length=500)
    message_id = models.CharField(max_length=255)
    subject = models.CharField(max_length=500, blank=True)
    from_addr = models.CharField(max_length=320, blank=True)
    date_header = models.CharField(max_length=120, blank=True)
    size = models.PositiveIntegerField(default=0)
    raw_bytes = models.BinaryField(blank=True, default=b"")
    flags = models.TextField(blank=True)
    internaldate = models.CharField(max_length=64, blank=True)
    imported = models.BooleanField(default=False)

    class Meta:
        unique_together = [("job", "folder", "message_id")]
        indexes = [models.Index(fields=["job", "folder"])]


class SchedulerHeartbeat(models.Model):
    """Last time the backup scheduler process completed a tick.

    Lets the UI say "the scheduler isn't running" instead of silently never
    backing anything up when the container isn't deployed.
    """

    key = models.CharField(max_length=50, unique=True, default="backup-scheduler")
    last_seen = models.DateTimeField(default=timezone.now)

    def __str__(self) -> str:
        return f"{self.key} @ {self.last_seen:%Y-%m-%d %H:%M:%S}"


class BackupFolder(models.Model):
    """One IMAP folder discovered on a BackupJob's mailbox.

    `selected` drives what the next run downloads; `server_count` is what the
    server reported the last time we listed or ran.
    """

    job = models.ForeignKey(BackupJob, on_delete=models.CASCADE, related_name="folders")
    name = models.CharField(max_length=500)
    delimiter = models.CharField(max_length=4, default="/")
    special_use = models.CharField(max_length=20, blank=True)
    selected = models.BooleanField(default=True)
    server_count = models.PositiveIntegerField(default=0)

    class Meta:
        unique_together = [("job", "name")]
        ordering = ["name"]

    def __str__(self) -> str:
        return self.name


class BackupMessage(models.Model):
    """One archived message. `raw_bytes` is the complete RFC822 source, so
    attachments are stored inline with the message and nothing else is needed
    to rebuild a full .eml."""

    job = models.ForeignKey(BackupJob, on_delete=models.CASCADE, related_name="messages")
    folder = models.CharField(max_length=500)
    # 255 (not 500) keeps the unique index below InnoDB's 3072-byte key limit:
    # bigint FK + folder(500) + this, at 4 bytes per utf8mb4 char. Message-IDs
    # longer than this are replaced by their sha256 fallback id when archived.
    message_id = models.CharField(max_length=255)

    subject = models.CharField(max_length=500, blank=True)
    from_addr = models.CharField(max_length=320, blank=True)
    date_header = models.CharField(max_length=120, blank=True)
    attachment_count = models.PositiveIntegerField(default=0)
    size = models.PositiveIntegerField(default=0)

    raw_bytes = models.BinaryField(blank=True, default=b"")
    flags = models.TextField(blank=True)
    internaldate = models.CharField(max_length=64, blank=True)
    source_uid = models.PositiveIntegerField(default=0)

    class Meta:
        unique_together = [("job", "folder", "message_id")]
        indexes = [
            models.Index(fields=["job", "folder"]),
        ]


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
