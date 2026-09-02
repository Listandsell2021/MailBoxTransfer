from __future__ import annotations

import io
import json
import re
from datetime import datetime, timezone as dt_timezone
from urllib.parse import urlencode
import tempfile
import time
import zipfile

from django.http import (
    FileResponse, Http404, HttpRequest, HttpResponse, JsonResponse,
    HttpResponseBadRequest, StreamingHttpResponse,
)
from django.contrib import messages
from django.contrib.auth import authenticate, login as auth_login
from django.shortcuts import get_object_or_404, redirect, render
from django.urls import reverse
from django.utils import timezone
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_GET, require_POST

from django.core.paginator import Paginator
from django.db import transaction
from django.db.models import Count, Exists, OuterRef, Q

from django_otp import devices_for_user, login as otp_login, user_has_device
from django_otp.decorators import otp_required

from django.contrib.auth import update_session_auth_hash
from django.contrib.auth.forms import PasswordChangeForm

from .forms import (
    BackupJobForm, BackupScheduleForm, MigrationForm, ProfileForm, RestoreJobForm,
)
from .imap_client import ImapClient, auto_pair_folders
from .models import (
    AccessEvent, BackupJob, BackupMessage, FolderMapping, Migration,
    MessageRecord, PhaseRun, RestoreJob, UserProfile, VerificationReport,
)
from .credentials import recall as recall_password, remember as remember_password
from .phases import CleanupGate, launch_backup_then_transfer, launch_phase
from .runtime import STATE, Credentials, load_credentials
from .crypto import encrypt


# ---------------------------------------------------------------------------
# Auth — single entry point for Google login → 2FA setup/verify → app
# ---------------------------------------------------------------------------

def login(request: HttpRequest) -> HttpResponse:
    """Always renders the login page (credentials form + Google button).

    Already-verified users are sent into the app. Authed-but-not-verified
    users still see the page, with a 'Continue as X' shortcut to resume 2FA.
    """
    if request.user.is_authenticated and request.user.is_verified():
        return redirect("migrator:home")

    # Drain any pending Django messages (e.g. "Confirmation email sent to ...")
    # so they don't pile up as banners on the login page or pop up as toasts
    # on the next page the user visits. The login view only surfaces auth errors.
    list(messages.get_messages(request))

    error = None
    if request.method == "POST":
        username = (request.POST.get("username") or "").strip()
        password = request.POST.get("password") or ""

        # Turnstile gate: bots hammering /login/ get stopped before we even
        # touch the credentials. Skipped automatically when unconfigured (dev).
        from .turnstile import enforced, verify_token
        if enforced() and not verify_token(request.POST.get("cf-turnstile-response")):
            return render(request, "migrator/login.html", {
                "error": "Please complete the CAPTCHA and try again.",
            })

        user = authenticate(request, username=username, password=password)
        if user is not None:
            auth_login(
                request, user,
                backend="allauth.account.auth_backends.AuthenticationBackend",
            )
            return redirect("migrator:after_login")

        # Distinguish "wrong password" from "signed up, awaiting admin approval"
        # so users know what to do next. A correct password on an inactive
        # account means they're pending approval, not that they mistyped.
        from django.contrib.auth import get_user_model
        User = get_user_model()
        candidate = User.objects.filter(email__iexact=username).first() if username else None
        if candidate and not candidate.is_active and candidate.check_password(password):
            return render(request, "account/account_inactive.html")
        error = "Invalid email or password."

    return render(request, "migrator/login.html", {"error": error})


def after_login(request: HttpRequest) -> HttpResponse:
    """Post-authentication 2FA orchestrator.

    Called as LOGIN_REDIRECT_URL after Google OAuth, and from the login view
    after a successful credentials submission. Routes the user to TOTP setup
    if they have no device, OTP verification if they do, or the app if already
    verified. Anonymous users are bounced back to /login/.
    """
    if not request.user.is_authenticated:
        return redirect("migrator:login")
    if request.user.is_verified():
        return redirect("migrator:home")
    if not user_has_device(request.user):
        return redirect("two_factor:setup")
    return redirect("migrator:verify_otp")


def verify_otp(request: HttpRequest) -> HttpResponse:
    """OTP challenge for an already-authenticated user.

    two_factor:login is a full username/password+OTP wizard and re-prompts for
    credentials even when the user is authenticated, so we use this slim view
    instead — single 6-digit-code field, validates against any of the user's
    confirmed devices, then promotes the session to OTP-verified.
    """
    if not request.user.is_authenticated:
        return redirect("migrator:login")
    if request.user.is_verified():
        return redirect("migrator:home")

    devices = [d for d in devices_for_user(request.user) if d.confirmed]
    if not devices:
        return redirect("two_factor:setup")

    error = None
    if request.method == "POST":
        token = (request.POST.get("token") or "").strip().replace(" ", "")
        for device in devices:
            if device.verify_token(token):
                otp_login(request, device)
                return redirect("migrator:home")
        error = "Invalid code. Try again."

    return render(request, "migrator/verify_otp.html", {"error": error})


# ---------------------------------------------------------------------------
# Ownership scoping
# ---------------------------------------------------------------------------

def _is_admin(user) -> bool:
    """A user counts as 'admin' if they're a superuser or staff. Admins see
    every migration in the system; everyone else sees only their own."""
    return bool(user and user.is_authenticated and (user.is_superuser or user.is_staff))


def _user_migrations(user):
    """Queryset of migrations VISIBLE to `user`. Admins see everything; regular
    users see only rows they own. Use this for read-only views (index, report)."""
    if _is_admin(user):
        return Migration.objects.all()
    return Migration.objects.filter(owner=user)


def _humanize_bytes(n: int | None) -> str:
    """Format a byte count as a short human-readable string. 0 → '0 B'."""
    n = int(n or 0)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024 or unit == "TB":
            return f"{n:.1f} {unit}" if unit != "B" else f"{n} B"
        n /= 1024
    return f"{n:.1f} TB"


def _editable_migrations(user):
    """Queryset of migrations the user can ACT on (edit, run, backup, delete).

    Admins can act on every migration, not only their own: they run this
    service, and a stuck mailbox belonging to a user who has gone home is
    theirs to fix. That is a deliberate reversal of the earlier rule — it does
    mean an admin can delete another user's archived mail, so the delete
    confirmation names the owner.
    """
    if not (user and user.is_authenticated):
        return Migration.objects.none()
    if _is_admin(user):
        return Migration.objects.all()
    return Migration.objects.filter(owner=user)


# ---------------------------------------------------------------------------
# Profile / notification preferences
# ---------------------------------------------------------------------------

@otp_required(login_url="migrator:login")
def profile(request: HttpRequest) -> HttpResponse:
    profile_obj, _ = UserProfile.objects.get_or_create(user=request.user)

    password_form = PasswordChangeForm(request.user)
    notif_form = ProfileForm(instance=profile_obj)

    if request.method == "POST":
        which = request.POST.get("form_name", "")
        if which == "password":
            password_form = PasswordChangeForm(request.user, request.POST)
            if password_form.is_valid():
                user = password_form.save()
                update_session_auth_hash(request, user)
                messages.success(request, "Password changed.")
                return redirect("migrator:profile")
        elif which == "notifications":
            notif_form = ProfileForm(request.POST, instance=profile_obj)
            if notif_form.is_valid():
                notif_form.save()
                messages.success(request, "Notification settings saved.")
                return redirect("migrator:profile")

    return render(request, "migrator/profile.html", {
        "password_form": password_form,
        "form": notif_form,
        "account_email": request.user.email,
        "account_username": request.user.get_username(),
        "date_joined": request.user.date_joined,
        "nav_active": "profile",
    })


# ---------------------------------------------------------------------------
# Home dashboard (aggregate stats + recent migrations)
# ---------------------------------------------------------------------------

def _current_phase_runs(runs):
    """Narrow a PhaseRun queryset to the latest attempt of each phase per
    migration. Every run of a phase inserts a new row, so an old failure sits
    in the table forever next to the successful re-run that replaced it — this
    keeps only the row that reflects the phase's state right now (same 'newest
    id wins' rule as _phase_summary)."""
    newer = PhaseRun.objects.filter(
        migration_id=OuterRef("migration_id"),
        phase=OuterRef("phase"),
        id__gt=OuterRef("id"),
    )
    return runs.annotate(_superseded=Exists(newer)).filter(_superseded=False)


@otp_required(login_url="migrator:login")
def home(request: HttpRequest) -> HttpResponse:
    """Top-level dashboard. Admin sees system-wide numbers; everyone else sees
    only the migrations they own."""
    is_admin = _is_admin(request.user)
    qs = _user_migrations(request.user)

    total_migrations = qs.count()
    msg_qs = MessageRecord.objects.filter(migration__in=qs)
    total_messages = msg_qs.count()
    total_transferred = msg_qs.filter(transferred=True).count()
    total_backed_up = msg_qs.filter(backed_up=True).count()

    # Success rate = transferred / backed_up across all owned migrations.
    success_rate = (
        round(100 * total_transferred / total_backed_up) if total_backed_up else 0
    )

    running_phases = PhaseRun.objects.filter(
        migration__in=qs, status=PhaseRun.STATUS_RUNNING,
    ).count()

    # Recent 5 migrations + a per-row status pill matching the report logic.
    recent = list(qs.order_by("-created_at")[:5])
    for m in recent:
        phases = _phase_summary(m)
        m.overall_status = _overall_status(phases)

    user_count = None
    pending_approvals = 0
    if is_admin:
        from django.contrib.auth import get_user_model
        UserModel = get_user_model()
        user_count = UserModel.objects.filter(is_superuser=False).count()
        pending_approvals = (
            UserModel.objects.filter(is_active=False, is_superuser=False).count()
        )

    # Failed phases, scoped to what the user can see. Only failures that are
    # still the latest attempt of their phase count: re-running a phase that
    # succeeds must clear the old failure, otherwise the dashboard keeps
    # reporting an error the user has already fixed.
    from datetime import timedelta
    still_current_failures = _current_phase_runs(
        PhaseRun.objects.filter(migration__in=qs, status=PhaseRun.STATUS_FAILED)
    )
    failed_24h_count = still_current_failures.filter(
        finished_at__gte=timezone.now() - timedelta(hours=24)
    ).count()
    recent_failures = list(
        still_current_failures
        .select_related("migration", "migration__owner")
        .order_by("-finished_at")[:5]
    )

    # Total stored bytes (the LONGBLOB column on MessageRecord.raw_bytes).
    from django.db.models import Sum
    storage_bytes = msg_qs.aggregate(total=Sum("size"))["total"] or 0
    storage_display = _humanize_bytes(storage_bytes)

    # Backups and restores are always the signed-in user's own — never
    # system-wide, even for an admin, because they hold mail content that only
    # the owner may see.
    backup_jobs = BackupJob.objects.filter(owner=request.user)
    backup_msg_qs = BackupMessage.objects.filter(job__in=backup_jobs)
    backup_agg = backup_msg_qs.aggregate(n=Count("id"), size=Sum("size"))
    scheduled_jobs = backup_jobs.exclude(schedule=BackupJob.SCHEDULE_OFF)
    next_backup = (
        scheduled_jobs.filter(next_run_at__isnull=False).order_by("next_run_at").first()
    )
    recent_backups = list(
        backup_jobs.order_by("-finished_at", "-created_at")[:5]
    )
    for job in recent_backups:
        job.message_count = backup_msg_qs.filter(job=job).count()

    restore_jobs = _owned_restore_jobs(request.user)
    restore_agg = restore_jobs.aggregate(imported=Sum("imported"), runs=Count("id"))
    recent_restores = list(
        restore_jobs.select_related("source_backup")
        .order_by("-finished_at", "-created_at")[:5]
    )

    from .scheduler import health
    scheduler_health = health() if scheduled_jobs.exists() else None

    return render(request, "migrator/home.html", {
        "backup_job_count": backup_jobs.count(),
        "backup_message_count": backup_agg["n"] or 0,
        "backup_storage_display": _humanize_bytes(backup_agg["size"] or 0),
        "scheduled_backup_count": scheduled_jobs.count(),
        "next_backup": next_backup,
        "recent_backups": recent_backups,
        "failed_backup_count": backup_jobs.filter(
            status=BackupJob.STATUS_FAILED).count(),
        "restore_run_count": restore_agg["runs"] or 0,
        "restore_imported_count": restore_agg["imported"] or 0,
        "recent_restores": recent_restores,
        "scheduler": scheduler_health,
        "nav_active": "home",
        "is_admin_view": is_admin,
        "total_migrations": total_migrations,
        "total_messages": total_messages,
        "total_transferred": total_transferred,
        "total_backed_up": total_backed_up,
        "success_rate": success_rate,
        "running_phases": running_phases,
        "recent": recent,
        "user_count": user_count,
        "pending_approvals": pending_approvals,
        "failed_24h_count": failed_24h_count,
        "recent_failures": recent_failures,
        "storage_bytes": storage_bytes,
        "storage_display": storage_display,
    })


# ---------------------------------------------------------------------------
# Index / list
# ---------------------------------------------------------------------------

PAGE_SIZES = [10, 20, 50, 100]
DEFAULT_PAGE_SIZE = 20


def _page_size(request) -> int:
    """The rows-per-page the user asked for, or the default if it's nonsense."""
    try:
        per = int(request.GET.get("per", DEFAULT_PAGE_SIZE))
    except (TypeError, ValueError):
        return DEFAULT_PAGE_SIZE
    return per if per in PAGE_SIZES else DEFAULT_PAGE_SIZE


def _page_numbers(page, paginator, window: int = 1) -> list:
    """The page numbers to show — first, last, and a window around the current
    one — with None standing in for each elided run. 41 pages shouldn't mean 41
    links.
    """
    last = paginator.num_pages
    wanted = {1, last} | {
        n for n in range(page.number - window, page.number + window + 1)
        if 1 <= n <= last
    }
    items, previous = [], 0
    for n in sorted(wanted):
        if previous and n - previous > 1:
            items.append(None)
        items.append(n)
        previous = n
    return items


def _paginate(request, rows: list, keep: dict) -> dict:
    """Slice one fully built list into pages. -> context for _pagination.html.

    Paginator runs over the list rather than the queryset because these lists
    are already materialised — status, sizes and counts are all worked out in
    Python — so there is no query left to defer.

    `keep` is what the pager's links must carry over (sort, status, search);
    each link appends its own `per` and `page`.
    """
    per = _page_size(request)
    paginator = Paginator(rows, per)
    page = paginator.get_page(request.GET.get("page"))
    prefix = urlencode(keep)
    return {
        "page_obj": page,
        "paginator": paginator,
        "per_page": per,
        "page_sizes": PAGE_SIZES,
        "page_numbers": _page_numbers(page, paginator),
        # Every link in the pager is "?{{ list_query }}per=N&page=N".
        "list_query": prefix + "&" if prefix else "",
        # Shown for any non-empty list, so the three lists carry the same
        # footer and the page size is always there to change. The page links
        # themselves only appear when there is more than one page.
        "show_pager": paginator.count > 0,
    }


def _sort_links(columns, sort: str, direction: str, keep: dict,
                desc_first=frozenset()) -> dict:
    """Where each sortable header points, and which arrow it shows.

    Clicking the active column flips it; a fresh column opens ascending, except
    the ones in `desc_first` — dates and counts, where "sort by this" plainly
    means newest or biggest first. `keep` is the search and status filter, which
    ride along so sorting never quietly drops them.
    """
    links = {}
    for column in columns:
        active = column == sort
        if active:
            nxt = "desc" if direction == "asc" else "asc"
        else:
            nxt = "desc" if column in desc_first else "asc"
        links[column] = {
            "url": "?" + urlencode({"sort": column, "dir": nxt, **keep}),
            "active": active,
            "dir": direction if active else "",
        }
    return links


_LONG_AGO = datetime.min.replace(tzinfo=dt_timezone.utc)   # never ran, never signed in
_FOREVER = datetime.max.replace(tzinfo=dt_timezone.utc)    # nothing scheduled


def _text_key(value) -> str:
    """Case-insensitive sort key — "alpha" belongs beside "Alpha", not after Z."""
    return (value or "").strip().lower()


def _sort_rows(rows: list, sorts: dict, sort: str, direction: str) -> list:
    """Order a list by the chosen column, in place.

    Sorting happens in Python, after the view has decorated each row, because
    the interesting columns aren't fields: a job's status is derived from its
    run, and counts, sizes and storage are aggregated on afterwards.

    The pk pass runs first and Python's sort is stable, so rows that tie stay
    newest-first whichever way the column points — no reshuffling between page
    loads.
    """
    rows.sort(key=lambda r: -r.pk)
    rows.sort(key=sorts[sort], reverse=(direction == "desc"))
    return rows


# Sortable columns on the migrations list -> the field to order by. `status`
# is None because it isn't a column: it's derived from the phase runs, so it is
# ranked in Python below.
MIGRATION_SORTS = {
    "label": "name",
    "owner": "owner__username",
    "source": "old_username",
    "destination": "new_username",
    "status": None,
    "created": "created_at",
}

# Ascending status means least-far-along first, which is what someone sorting
# by status actually wants: alphabetical would put "complete" above
# "in-progress" and tell them nothing.
STATUS_RANK = {
    "not-started": 0,
    "interrupted": 1,
    "in-progress": 2,
    "backed-up": 3,
    "transferred": 4,
    "verified": 5,
    "complete": 6,
}


@otp_required(login_url="migrator:login")
def index(request: HttpRequest) -> HttpResponse:
    sort = request.GET.get("sort", "created")
    if sort not in MIGRATION_SORTS:
        sort = "created"
    direction = "asc" if request.GET.get("dir") == "asc" else "desc"
    wanted_status = request.GET.get("status", "")
    if wanted_status not in STATUS_RANK:
        wanted_status = ""
    search = request.GET.get("q", "").strip()

    field = MIGRATION_SORTS[sort]
    base = _user_migrations(request.user)
    all_count = base.count()                # the list's size before searching
    qs = (
        base
        .select_related("owner")            # the Owner column, in one query
        .annotate(phase_count=Count("phase_runs"))
    )
    if search:
        # Every column on the row is worth searching: someone looking up a
        # mailbox may remember the label, either address, either server, or
        # who set it up.
        qs = qs.filter(
            Q(name__icontains=search)
            | Q(old_username__icontains=search)
            | Q(new_username__icontains=search)
            | Q(old_host__icontains=search)
            | Q(new_host__icontains=search)
            | Q(owner__username__icontains=search)
        )
    # A stable tiebreak on -id keeps rows from shuffling between page loads when
    # a sort key repeats — every mailbox on one domain shares a host, say.
    qs = qs.order_by(
        *([f"{'' if direction == 'asc' else '-'}{field}", "-id"] if field else ["-created_at"])
    )

    migrations = list(qs)
    statuses = _overall_statuses(migrations)
    is_admin = _is_admin(request.user)
    for m in migrations:
        m.overall_status = statuses[m.pk]
        # Admins manage every row; everyone else only their own.
        m.can_manage = is_admin or m.owner_id == request.user.id

    # Counted before filtering, so the dropdown always shows the whole picture
    # rather than only the slice already on screen.
    counts: dict[str, int] = {}
    for m in migrations:
        counts[m.overall_status] = counts.get(m.overall_status, 0) + 1
    total = len(migrations)

    if wanted_status:
        migrations = [m for m in migrations if m.overall_status == wanted_status]
    if field is None:
        migrations.sort(
            key=lambda m: (STATUS_RANK[m.overall_status], -m.pk),
            reverse=(direction == "desc"),
        )

    keep = {k: v for k, v in (("status", wanted_status), ("q", search)) if v}
    shown_count = len(migrations)
    # Sorting comes first: a page is a window onto the ordered list, not the
    # other way round.
    pager = _paginate(request, migrations, {**keep, "sort": sort, "dir": direction})

    return render(request, "migrator/index.html", {
        "migrations": pager["page_obj"].object_list,
        "is_admin_view": _is_admin(request.user),
        "nav_active": "migrations",
        "sortcols": _sort_links(MIGRATION_SORTS, sort, direction,
                                {**keep, "per": pager["per_page"]},
                                desc_first={"created"}),
        "sort": sort,
        "dir": direction,
        "status_filter": wanted_status,
        "status_choices": [
            {"value": v, "label": v.replace("-", " ").title(), "count": counts.get(v, 0)}
            for v in STATUS_RANK
        ],
        "search": search,
        # total_count is the search result set (what the status dropdown counts
        # against); all_count is the whole list, so the toolbar can say "8 of 39".
        "total_count": total,
        "all_count": all_count,
        "shown_count": shown_count,
        # Everything except the sort, for links that should keep the search on.
        "keep_query": urlencode(keep),
        **pager,
    })


# Sortable columns on the users list. Storage is aggregated onto each row
# below, so like the job lists this sorts in Python rather than in SQL.
USER_SORTS = {
    # The default. Pending signups first, then staff, then alphabetical — the
    # order the page had before it was sortable, expressed as one key so the
    # Status header can own it.
    "status": lambda u: (u.is_active, not u.is_staff, _text_key(u.get_username())),
    "user": lambda u: _text_key(
        f"{u.first_name} {u.last_name}".strip() or u.get_username()
    ),
    "role": lambda u: (not u.is_staff, _text_key(u.get_username())),
    "migrations": lambda u: u.migration_count,
    "storage": lambda u: u.storage_bytes,
    "last_login": lambda u: u.last_login or _LONG_AGO,
}

# Counts and dates open biggest / most recent first.
USER_SORTS_DESC_FIRST = frozenset({"migrations", "storage", "last_login"})


@otp_required(login_url="migrator:login")
def users_list(request: HttpRequest) -> HttpResponse:
    """Admin-only: every non-superuser and how many migrations they own.

    Accepts ?status=active|pending|all (default: all) for the filter chips,
    plus the ?q / ?sort / ?dir / ?per / ?page the other lists take. Inactive
    users sort first by default so new signups stand out.
    """
    if not _is_admin(request.user):
        raise Http404()
    from django.contrib.auth import get_user_model
    User = get_user_model()

    base_qs = (
        User.objects.exclude(is_superuser=True)
        .annotate(migration_count=Count("migrations"))
    )

    status = (request.GET.get("status") or "all").lower()
    if status == "active":
        filtered_qs = base_qs.filter(is_active=True)
    elif status == "pending":
        filtered_qs = base_qs.filter(is_active=False)
    else:
        status = "all"
        filtered_qs = base_qs

    search = request.GET.get("q", "").strip()
    if search:
        # Whichever of the four an admin half-remembers about someone.
        filtered_qs = filtered_qs.filter(
            Q(username__icontains=search)
            | Q(email__icontains=search)
            | Q(first_name__icontains=search)
            | Q(last_name__icontains=search)
        )

    sort = request.GET.get("sort", "status")
    if sort not in USER_SORTS:
        sort = "status"
    # Unlike the job lists this one defaults to ascending: its default column is
    # Status, and ascending there means "signups waiting on me, at the top".
    direction = "desc" if request.GET.get("dir") == "desc" else "asc"

    users = list(filtered_qs)

    # Compute per-user storage in one query, then attach to each user object.
    from django.db.models import Sum
    storage_by_user: dict[int, int] = {}
    if users:
        for row in (
            MessageRecord.objects
            .filter(migration__owner__in=[u.id for u in users])
            .values("migration__owner")
            .annotate(total=Sum("size"))
        ):
            storage_by_user[row["migration__owner"]] = row["total"] or 0
    for u in users:
        u.storage_bytes = storage_by_user.get(u.id, 0)
        u.storage_display = _humanize_bytes(u.storage_bytes)

    # Attach a "signin_methods" set to each user so the template can show
    # Google / Email badges. A user can have one OR both — they're not exclusive.
    from allauth.socialaccount.models import SocialAccount
    social_providers: dict[int, set[str]] = {}
    if users:
        rows = SocialAccount.objects.filter(
            user__in=[u.id for u in users]
        ).values_list("user_id", "provider")
        for uid, provider in rows:
            social_providers.setdefault(uid, set()).add(provider)
    for u in users:
        providers = social_providers.get(u.id, set())
        methods = set(providers)
        # If they can authenticate with a password (usable hash), count Email too.
        # Pure-OAuth users have unusable passwords (set_unusable_password() in allauth).
        if u.has_usable_password():
            methods.add("email")
        u.signin_methods = methods  # e.g. {"google"}, {"email"}, or {"google", "email"}

    _sort_rows(users, USER_SORTS, sort, direction)

    stats = {
        "total":   base_qs.count(),
        "active":  base_qs.filter(is_active=True).count(),
        "pending": base_qs.filter(is_active=False).count(),
    }

    keep = {k: v for k, v in (("status", status), ("q", search)) if v}
    pager = _paginate(request, users, {**keep, "sort": sort, "dir": direction})

    return render(request, "migrator/users.html", {
        "users": pager["page_obj"].object_list,
        "stats": stats,
        "status_filter": status,
        "search": search,
        "sort": sort,
        "dir": direction,
        "sortcols": _sort_links(USER_SORTS, sort, direction,
                                {**keep, "per": pager["per_page"]},
                                desc_first=USER_SORTS_DESC_FIRST),
        # The filter chips keep everything except the status they set.
        "chip_query": urlencode({**{k: v for k, v in (("q", search),) if v},
                                 "sort": sort, "dir": direction,
                                 "per": pager["per_page"]}),
        "nav_active": "users",
        **pager,
    })


@otp_required(login_url="migrator:login")
@require_POST
def toggle_user_active(request: HttpRequest, user_id: int) -> HttpResponse:
    """Admin-only: flip a user's is_active flag.

    Guard rails:
      * Admin can't disable themselves (would lock them out of the app).
      * Admin can't disable other superusers via this endpoint (use /admin/).
    """
    if not _is_admin(request.user):
        raise Http404()
    from django.contrib.auth import get_user_model
    User = get_user_model()
    target = get_object_or_404(User, pk=user_id)

    if target.pk == request.user.pk:
        messages.error(request, "You can't deactivate your own account.")
        return redirect("migrator:users")
    if target.is_superuser and request.user.pk != target.pk:
        messages.error(
            request,
            "Superusers can't be toggled from here. Use the Django admin if needed.",
        )
        return redirect("migrator:users")

    was_active = target.is_active
    target.is_active = not target.is_active
    target.save(update_fields=["is_active"])
    label = target.get_username() or target.email

    if target.is_active:
        # Approval transition (inactive → active): tell the user they're in.
        # This is the ONLY signup-related email we send, and only to an account
        # an admin just vetted — so it never lands on a bot/harvested address.
        if not was_active:
            emailed = _send_approval_email(request, target)
            if emailed:
                messages.success(request, f"Activated {label} and emailed them. They can sign in now.")
            else:
                messages.success(request, f"Activated {label}. They can sign in now (no email on file to notify).")
        else:
            messages.success(request, f"Activated {label}. They can sign in now.")
    else:
        messages.success(request, f"Deactivated {label}.")
    return redirect("migrator:users")


def _send_approval_email(request: HttpRequest, user) -> bool:
    """Send the one-and-only 'your account is approved' email. Returns True if
    an email was actually dispatched. Never raises — approval must not fail just
    because mail delivery hiccups."""
    to_addr = (user.email or "").strip()
    if not to_addr:
        return False
    from django.core.mail import send_mail
    login_url = request.build_absolute_uri(reverse("migrator:login"))
    name = (user.first_name or "").strip() or "there"
    try:
        send_mail(
            subject="Your Mailbox Transfer account is approved",
            message=(
                f"Hi {name},\n\n"
                f"Your Mailbox Transfer account has been approved. You can now sign in:\n"
                f"  {login_url}\n\n"
                f"On first sign-in you'll set up two-factor authentication.\n"
            ),
            from_email=None,  # uses DEFAULT_FROM_EMAIL
            recipient_list=[to_addr],
            fail_silently=True,
        )
        return True
    except Exception:
        return False


@otp_required(login_url="migrator:login")
@require_POST
def delete_user(request: HttpRequest, user_id: int) -> HttpResponse:
    """Admin-only: hard-delete a user. CASCADE wipes their migrations and stored
    raw bytes — irreversible. The confirm dialog in users.html surfaces this.

    Guards: no self-delete, no deleting superusers via this endpoint.
    """
    if not _is_admin(request.user):
        raise Http404()
    from django.contrib.auth import get_user_model
    User = get_user_model()
    target = get_object_or_404(User, pk=user_id)

    if target.pk == request.user.pk:
        messages.error(request, "You can't delete your own account.")
        return redirect("migrator:users")
    if target.is_superuser:
        messages.error(
            request,
            "Superusers can't be deleted from here. Use the Django admin if needed.",
        )
        return redirect("migrator:users")

    label = target.get_username() or target.email
    cascaded = target.migrations.count()
    target.delete()
    if cascaded:
        messages.success(
            request,
            f"Deleted {label} and {cascaded} of their migration(s) (and stored backups).",
        )
    else:
        messages.success(request, f"Deleted {label}.")
    return redirect("migrator:users")


# ---------------------------------------------------------------------------
# Admin notifications feed (page visits + signups)
# ---------------------------------------------------------------------------

@otp_required(login_url="migrator:login")
def notifications(request: HttpRequest) -> HttpResponse:
    """Admin-only activity feed: auth-page visits and account signups, each
    with IP + time. Accepts ?kind=visit|signup|all (default all).

    Visiting the page marks everything currently shown as seen, which clears
    the nav badge.
    """
    if not _is_admin(request.user):
        raise Http404()

    kind = (request.GET.get("kind") or "all").lower()
    base_qs = AccessEvent.objects.all()
    if kind == AccessEvent.KIND_VISIT:
        events_qs = base_qs.filter(kind=AccessEvent.KIND_VISIT)
    elif kind == AccessEvent.KIND_SIGNUP:
        events_qs = base_qs.filter(kind=AccessEvent.KIND_SIGNUP)
    else:
        kind = "all"
        events_qs = base_qs

    events = list(events_qs[:500])

    # Mark the unseen ones seen so the badge clears. Do it after slicing so we
    # only touch what the admin is actually looking at.
    unseen_ids = [e.id for e in events if not e.seen]
    if unseen_ids:
        AccessEvent.objects.filter(id__in=unseen_ids).update(seen=True)

    stats = {
        "total":   base_qs.count(),
        "visits":  base_qs.filter(kind=AccessEvent.KIND_VISIT).count(),
        "signups": base_qs.filter(kind=AccessEvent.KIND_SIGNUP).count(),
    }

    return render(request, "migrator/notifications.html", {
        "events": events,
        "stats": stats,
        "kind_filter": kind,
        "nav_active": "notifications",
    })


@otp_required(login_url="migrator:login")
@require_POST
def clear_notifications(request: HttpRequest) -> HttpResponse:
    """Admin-only: delete all recorded access events."""
    if not _is_admin(request.user):
        raise Http404()
    deleted, _ = AccessEvent.objects.all().delete()
    messages.success(request, f"Cleared {deleted} notification(s).")
    return redirect("migrator:notifications")


# ---------------------------------------------------------------------------
# Screen 1 - Configuration + folder mapping
# ---------------------------------------------------------------------------

@otp_required(login_url="migrator:login")
def config(request: HttpRequest, migration_id: int | None = None) -> HttpResponse:
    migration = get_object_or_404(_editable_migrations(request.user), pk=migration_id) if migration_id else None

    if request.method == "POST":
        form = MigrationForm(request.POST, instance=migration)
        if form.is_valid():
            obj = form.save(commit=False)
            if obj.owner_id is None:
                obj.owner = request.user
            obj.save()
            existing = load_credentials(obj.pk) or Credentials()
            # Typed > already on this migration > saved for that mailbox
            # earlier. The last step is what stops a user re-typing the same
            # mailbox password for every migration they set up.
            new_old = (
                form.cleaned_data.get("old_password") or existing.old_password
                or recall_password(obj.owner_id, obj.old_host, obj.old_username)
            )
            new_new = (
                form.cleaned_data.get("new_password") or existing.new_password
                or recall_password(obj.owner_id, obj.new_host, obj.new_username)
            )
            # Whatever we ended up with is this mailbox's password from now on.
            remember_password(obj.owner_id, obj.old_host, obj.old_username, new_old)
            remember_password(obj.owner_id, obj.new_host, obj.new_username, new_new)
            STATE.set_credentials(obj.pk, Credentials(
                old_password=new_old,
                new_password=new_new,
            ))
            # Persist encrypted copies so creds survive process restart. Skip
            # update for either side that was left blank and had no prior value.
            update_fields = []
            if new_old:
                obj.old_password_enc = encrypt(new_old)
                update_fields.append("old_password_enc")
            if new_new:
                obj.new_password_enc = encrypt(new_new)
                update_fields.append("new_password_enc")
            if update_fields:
                obj.save(update_fields=update_fields)
            _persist_mapping_payload(obj, request.POST.get("mapping_payload", ""))
            _provision_destination_folders(request, obj)
            had_mapping = obj.folder_mappings.exclude(action=FolderMapping.ACTION_SKIP).exists()
            if had_mapping and load_credentials(obj.pk):
                return redirect("migrator:dashboard", migration_id=obj.pk)
            return redirect("migrator:config_edit", migration_id=obj.pk)
    else:
        form = MigrationForm(instance=migration)

    has_creds = bool(migration and load_credentials(migration.pk))
    mappings = (
        list(migration.folder_mappings.order_by("old_folder")) if migration else []
    )
    can_proceed = bool(
        migration
        and has_creds
        and any(m.action != FolderMapping.ACTION_SKIP for m in mappings)
    )
    # Total mail on the source, as of the last Test connection. Rendered from
    # the stored per-folder counts so the number survives a reload — the JS
    # status line only exists until the page is refreshed. None when nothing
    # has been counted yet, which reads differently from a genuine zero.
    counted = [m.old_message_count for m in mappings if m.old_message_count is not None]
    return render(request, "migrator/config.html", {
        "form": form,
        "migration": migration,
        "mappings": mappings,
        "has_creds": has_creds,
        "can_proceed": can_proceed,
        "source_message_total": sum(counted) if counted else None,
        "nav_active": "migrations",
    })


def _folder_counts(client, folders) -> dict[str, int | None]:
    """{folder name: message count} for an open connection.

    SELECT is what the backup phase counts with, so these are the same numbers
    the run will report. A folder that can't be opened at all (a Noselect
    container, or one the server refuses) maps to None: unknown, not zero.
    """
    counts: dict[str, int | None] = {}
    for f in folders:
        try:
            counts[f.name] = client.select(f.name, readonly=True)
        except Exception:
            counts[f.name] = None
    return counts


@otp_required(login_url="migrator:login")
@require_POST
def test_connection(request: HttpRequest, migration_id: int) -> HttpResponse:
    migration = get_object_or_404(_editable_migrations(request.user), pk=migration_id)
    creds = load_credentials(migration_id)
    if not creds:
        return JsonResponse({"ok": False, "error": "No credentials saved yet. Save the form first."}, status=400)
    try:
        with ImapClient(migration.old_host, migration.old_port, migration.old_username,
                        creds.old_password, use_ssl=migration.old_use_ssl) as old, \
             ImapClient(migration.new_host, migration.new_port, migration.new_username,
                        creds.new_password, use_ssl=migration.new_use_ssl) as new:
            old_folders = old.list_folders()
            new_folders = new.list_folders()
            # How much mail is actually on each side. Knowing "135 messages"
            # up front is the difference between a migration you can plan and
            # one you start blind — and it is the same SELECT the backup phase
            # does anyway, just an hour earlier.
            old_counts = _folder_counts(old, old_folders)
            new_counts = _folder_counts(new, new_folders)
    except Exception as exc:
        return JsonResponse({"ok": False, "error": str(exc)}, status=400)

    rows = auto_pair_folders(old_folders, new_folders)
    for r in rows:
        r["old_count"] = old_counts.get(r["old"])

    migration.folder_mappings.all().delete()
    FolderMapping.objects.bulk_create([
        FolderMapping(
            migration=migration,
            old_folder=r["old"],
            new_folder=r["new"],
            action=r["action"],
            pairing_reason=r["pairing_reason"],
            special_use=r["special_use"],
            old_message_count=r["old_count"],
        )
        for r in rows
    ])

    return JsonResponse({
        "ok": True,
        "old_folder_count": len(old_folders),
        "new_folder_count": len(new_folders),
        "old_message_total": sum(v for v in old_counts.values() if v),
        "new_message_total": sum(v for v in new_counts.values() if v),
        "new_folder_names": sorted(f.name for f in new_folders),
        "rows": rows,
    })


def _provision_destination_folders(request: HttpRequest, migration: Migration) -> None:
    """For every mapping with action=create, ensure the folder exists on the
    destination IMAP server. Flashes user-facing messages with the outcome.
    No-op if there are no action=create rows."""
    creates = list(migration.folder_mappings.filter(action=FolderMapping.ACTION_CREATE))
    if not creates:
        return

    creds = load_credentials(migration.pk)
    if not creds or not creds.new_password:
        messages.warning(
            request,
            f"{len(creates)} folder(s) marked 'Create' could not be created: "
            "destination password is not in memory. Re-enter it and save again.",
        )
        return

    created: list[str] = []
    already: list[str] = []
    failed: list[str] = []
    try:
        with ImapClient(
            migration.new_host, migration.new_port, migration.new_username,
            creds.new_password, use_ssl=migration.new_use_ssl,
        ) as new:
            existing = {f.name for f in new.list_folders()}
            for m in creates:
                # Keep verbatim - the transfer phase resolves the same way, and
                # stripping here would create a folder it then fails to find.
                dst = m.new_folder or m.old_folder
                if not dst.strip():
                    continue
                if dst in existing:
                    already.append(dst)
                    continue
                try:
                    new.create_folder(dst)
                    created.append(dst)
                    existing.add(dst)
                except Exception as exc:
                    failed.append(f"{dst} ({exc})")
    except Exception as exc:
        messages.error(request, f"Could not connect to destination to create folders: {exc}")
        return

    if created:
        messages.success(
            request,
            f"Created {len(created)} folder(s) on destination: {', '.join(created)}",
        )
    if already and not created and not failed:
        messages.info(
            request,
            f"Destination already had {len(already)} folder(s) marked 'Create': {', '.join(already)}",
        )
    if failed:
        messages.error(request, "Failed to create: " + "; ".join(failed))


def _mapping_key(folder: str) -> str:
    """Key used to pair a payload row with an existing mapping row. MySQL's
    unique index compares VARCHARs ignoring trailing spaces, so a folder named
    'INBOX.Foo ' collides with 'INBOX.Foo' in the database even though the two
    differ in Python. Mirror that here or the lookup misses and the insert blows
    up with a duplicate-entry IntegrityError."""
    return folder.rstrip()


def _persist_mapping_payload(migration: Migration, raw: str) -> int:
    """Replace migration's mappings from a JSON payload. Returns row count saved.
    Empty/invalid payload is a no-op (returns 0)."""
    if not raw:
        return 0
    try:
        rows = json.loads(raw)
    except json.JSONDecodeError:
        return 0
    if not isinstance(rows, list):
        return 0

    by_old: dict[str, FolderMapping] = {}
    for m in migration.folder_mappings.all():
        # setdefault: any pre-existing near-duplicate rows lose and get deleted below.
        by_old.setdefault(_mapping_key(m.old_folder), m)

    keep_pks: set[int] = set()
    seen_keys: set[str] = set()
    to_update: list[FolderMapping] = []
    to_create: list[FolderMapping] = []
    for r in rows:
        if not isinstance(r, dict):
            continue
        # Keep the folder name verbatim - IMAP names may legitimately end in a
        # space and must match the server's name exactly during transfer.
        old = r.get("old") or ""
        if not old.strip():
            continue
        key = _mapping_key(old)
        if key in seen_keys:
            continue
        seen_keys.add(key)
        new = r.get("new") or ""
        action = r.get("action") or FolderMapping.ACTION_MAP
        if action not in {FolderMapping.ACTION_MAP, FolderMapping.ACTION_CREATE, FolderMapping.ACTION_SKIP}:
            action = FolderMapping.ACTION_MAP
        existing = by_old.get(key)
        if existing:
            existing.new_folder = new
            existing.action = action
            existing.pairing_reason = FolderMapping.PAIRING_MANUAL
            keep_pks.add(existing.pk)
            to_update.append(existing)
        else:
            to_create.append(FolderMapping(
                migration=migration, old_folder=old, new_folder=new,
                action=action, pairing_reason=FolderMapping.PAIRING_MANUAL,
            ))

    with transaction.atomic():
        # Delete before inserting so a row being replaced cannot collide.
        migration.folder_mappings.exclude(pk__in=keep_pks).delete()
        for m in to_update:
            m.save(update_fields=["new_folder", "action", "pairing_reason"])
        if to_create:
            FolderMapping.objects.bulk_create(to_create)
    return len(rows)


@otp_required(login_url="migrator:login")
@require_POST
def save_mapping(request: HttpRequest, migration_id: int) -> HttpResponse:
    migration = get_object_or_404(_editable_migrations(request.user), pk=migration_id)
    saved = _persist_mapping_payload(migration, request.POST.get("payload", ""))
    return JsonResponse({"ok": True, "saved": saved})


# ---------------------------------------------------------------------------
# Screen 2 - Dashboard
# ---------------------------------------------------------------------------

def _phase_summary(migration: Migration) -> dict[str, dict]:
    out = {}
    for phase, _label in PhaseRun.PHASE_CHOICES:
        last = (
            migration.phase_runs.filter(phase=phase).order_by("-id").first()
        )
        out[phase] = {
            "status": last.status if last else PhaseRun.STATUS_PENDING,
            "processed": last.processed if last else 0,
            "total": last.total if last else 0,
            "error": last.error if last else "",
            "started": last.started_at if last else None,
            "finished": last.finished_at if last else None,
            # Says "running" but its process stopped answering — the screens
            # offer Resume instead of a progress bar that will never move.
            "stalled": bool(last and last.is_stalled),
            # Ended because its process died, rather than because the work went
            # wrong. Worth distinguishing: nothing is broken, it just stopped.
            "interrupted": bool(last and last.interrupted),
        }
    return out


def _overall_status(phases: dict[str, dict]) -> str:
    """The one word that describes a migration, from its per-phase summary.

    Shared by the list, the home screen and the report so the three can't drift
    apart. Reads only `status`, `stalled` and `interrupted`, so it works on the
    trimmed summaries `_overall_statuses` builds as well as on full ones.

    What the migration is doing *now* outranks how far it has got: a live
    transfer sitting on top of a finished backup is "in progress", not
    "backed-up", and a phase whose process died is "interrupted" even though
    the earlier phases still show their green ticks. Only once nothing is
    running or waiting on a person does the ladder of completed phases decide.
    """
    running = [p for p in phases.values() if p["status"] == PhaseRun.STATUS_RUNNING]
    if any(not p["stalled"] for p in running):
        return "in-progress"
    if any(p["stalled"] or p["interrupted"] for p in phases.values()):
        return "interrupted"
    if phases["cleanup"]["status"] == PhaseRun.STATUS_SUCCESS:
        return "complete"
    if phases["verify"]["status"] == PhaseRun.STATUS_SUCCESS:
        return "verified"
    if phases["transfer"]["status"] == PhaseRun.STATUS_SUCCESS:
        return "transferred"
    if phases["backup"]["status"] == PhaseRun.STATUS_SUCCESS:
        return "backed-up"
    return "not-started"


def _overall_statuses(migrations) -> dict[int, str]:
    """{migration_id: overall status} for a whole page of migrations.

    One query for every phase run, rather than the four per row `_phase_summary`
    would cost — the list runs to a hundred migrations. `error` and `log_path`
    are deferred because a status pill never shows them and they carry whole
    tracebacks.
    """
    ids = [m.pk for m in migrations]
    latest: dict[tuple[int, str], PhaseRun] = {}
    for run in (
        PhaseRun.objects.filter(migration_id__in=ids)
        .defer("error", "log_path").order_by("id")
    ):
        # Ascending id, so the last write for a (migration, phase) is its
        # newest run — the same one _phase_summary picks.
        latest[(run.migration_id, run.phase)] = run

    out = {}
    for mid in ids:
        phases = {}
        for phase, _label in PhaseRun.PHASE_CHOICES:
            run = latest.get((mid, phase))
            phases[phase] = {
                "status": run.status if run else PhaseRun.STATUS_PENDING,
                "stalled": bool(run and run.is_stalled),
                "interrupted": bool(run and run.interrupted),
            }
        out[mid] = _overall_status(phases)
    return out


@otp_required(login_url="migrator:login")
def dashboard(request: HttpRequest, migration_id: int) -> HttpResponse:
    migration = get_object_or_404(_editable_migrations(request.user), pk=migration_id)
    summary = _phase_summary(migration)
    # Per side, not "some password exists". A migration holding only the
    # destination password used to look ready: Run was enabled, no warning
    # showed, and the blank source password went to the mail server, which
    # answered "[AUTHENTICATIONFAILED]" — a wrong-password message for a
    # missing-password problem. Backup reads the source; transfer and verify
    # need both ends.
    creds = load_credentials(migration_id)
    has_old = bool(creds and creds.old_password)
    has_new = bool(creds and creds.new_password)
    has_creds = has_old and has_new

    can_run = {
        "backup": has_old,
        "transfer": has_creds and summary["backup"]["status"] == PhaseRun.STATUS_SUCCESS,
        "verify": has_creds and summary["transfer"]["status"] == PhaseRun.STATUS_SUCCESS,
    }
    any_stalled = any(p["stalled"] for p in summary.values())
    cleanup_unlocked = (
        has_creds and summary["verify"]["status"] == PhaseRun.STATUS_SUCCESS
    )
    return render(request, "migrator/dashboard.html", {
        "migration": migration,
        "summary": summary,
        "can_run": can_run,
        "any_stalled": any_stalled,
        "cleanup_unlocked": cleanup_unlocked,
        "has_creds": has_creds,
        "missing_password_sides": [
            label for label, present in (
                (f"source ({migration.old_username})", has_old),
                (f"destination ({migration.new_username})", has_new),
            ) if not present
        ],
        "nav_active": "migrations",
    })


# The dashboard's "Backup + Transfer" button posts this in place of a phase
# name: one request that runs backup and then transfer without a second click.
CHAIN_BACKUP_TRANSFER = "backup_transfer"


def _credential_error(migration: Migration, needs_destination: bool) -> str | None:
    """Say which password is missing, or None when the phase can run.

    Checking "are there any credentials" is not enough: with only the
    destination password saved, backup signs in to the source with a blank one
    and the mail server reports an authentication failure — which reads as a
    wrong password rather than a missing one.
    """
    creds = load_credentials(migration.pk)
    missing = []
    if not (creds and creds.old_password):
        missing.append(f"source ({migration.old_username})")
    if needs_destination and not (creds and creds.new_password):
        missing.append(f"destination ({migration.new_username})")
    if not missing:
        return None
    return (
        "No password saved for the " + " and the ".join(missing) + " mailbox. "
        "Enter it on the configuration screen and save."
    )


@otp_required(login_url="migrator:login")
@require_POST
def start_phase(request: HttpRequest, migration_id: int, phase: str) -> HttpResponse:
    is_chain = phase == CHAIN_BACKUP_TRANSFER
    if not is_chain:
        if phase not in {p for p, _ in PhaseRun.PHASE_CHOICES}:
            return HttpResponseBadRequest("unknown phase")
        if phase == PhaseRun.PHASE_CLEANUP:
            return HttpResponseBadRequest("use cleanup endpoint")
    migration = get_object_or_404(_editable_migrations(request.user), pk=migration_id)
    # Backup only reads the source; everything else touches both ends.
    needs_destination = is_chain or phase != PhaseRun.PHASE_BACKUP
    error = _credential_error(migration, needs_destination)
    if error:
        return JsonResponse({"ok": False, "error": error}, status=400)
    if is_chain:
        return JsonResponse({"ok": True, "started": launch_backup_then_transfer(migration.pk)})
    started = launch_phase(migration.pk, phase)
    return JsonResponse({"ok": True, "started": started})


@otp_required(login_url="migrator:login")
@require_GET
def phase_status(request: HttpRequest, migration_id: int) -> HttpResponse:
    migration = get_object_or_404(_editable_migrations(request.user), pk=migration_id)
    return JsonResponse({"summary": {
        k: {**v, "started": v["started"].isoformat() if v["started"] else None,
            "finished": v["finished"].isoformat() if v["finished"] else None}
        for k, v in _phase_summary(migration).items()
    }})


@otp_required(login_url="migrator:login")
@require_POST
def resume_phase(request: HttpRequest, migration_id: int, phase: str) -> HttpResponse:
    """Pick a phase back up after the process running it died.

    The dashboard's Run button already does this (starting a phase resumes it,
    since every phase skips what it already did); this exists so the Report
    screen — where a stalled run is usually spotted — can offer the same thing
    without JavaScript, closing the dead run row on the way through.

    """
    from .supervisor import resume_phase_run

    if phase not in {p for p, _ in PhaseRun.PHASE_CHOICES}:
        return HttpResponseBadRequest("unknown phase")
    if phase == PhaseRun.PHASE_CLEANUP:
        return HttpResponseBadRequest("cleanup is re-run from the verification screen")
    migration = get_object_or_404(_editable_migrations(request.user), pk=migration_id)

    run = migration.phase_runs.filter(phase=phase).order_by("-id").first()
    label = dict(PhaseRun.PHASE_CHOICES).get(phase, phase)
    interrupted = run is not None and (run.is_stalled or run.interrupted)

    if run is None or not run.is_stalled:
        # Nothing dead to revive right now: it never ran, it is genuinely
        # alive, or the sweep already closed it. Starting it does the resuming.
        if not load_credentials(migration.pk):
            messages.error(request, "No credentials saved for this migration.")
        elif launch_phase(migration.pk, phase, resumed=interrupted):
            messages.success(
                request,
                f"{label} started — it skips everything already done, so it "
                f"carries on rather than starting over."
                if interrupted else f"{label} started.",
            )
        else:
            messages.info(request, f"{label} is already running.")
    else:
        resumed, reason = resume_phase_run(run)
        if resumed:
            messages.success(
                request,
                f"{label} was interrupted by a restart and has been resumed — "
                f"it carries on from the {run.processed} message(s) already done.",
            )
        else:
            messages.error(request, f"Could not resume {label}: {reason}.")

    return redirect(request.POST.get("next") or reverse("migrator:report", args=[migration.pk]))


# ---------------------------------------------------------------------------
# SSE log stream
# ---------------------------------------------------------------------------

@otp_required(login_url="migrator:login")
def log_snapshot(request: HttpRequest, migration_id: int) -> JsonResponse:
    """Return the current event-history buffer for a migration.

    Why: the SSE stream replays history on connect, but the JS log/phase
    handlers can't tell historical events from new ones — replaying a finished
    phase fires the reload/popup logic again. Rendering log lines from this
    snapshot at page-load and opening SSE from the returned max_seq separates
    the two cleanly.
    """
    migration = get_object_or_404(_editable_migrations(request.user), pk=migration_id)
    hub = STATE.hub(migration.pk)
    events, max_seq = hub.snapshot()
    return JsonResponse({"events": events, "max_seq": max_seq})


@otp_required(login_url="migrator:login")
@csrf_exempt
def sse_stream(request: HttpRequest, migration_id: int) -> StreamingHttpResponse:
    migration = get_object_or_404(_editable_migrations(request.user), pk=migration_id)
    return _sse_response(request, STATE.hub(migration.pk))


def _sse_response(request: HttpRequest, hub) -> StreamingHttpResponse:
    """Server-sent-events feed for one Hub, resuming from ?since / Last-Event-ID."""
    raw_since = request.META.get("HTTP_LAST_EVENT_ID") or request.GET.get("since") or "0"
    try:
        since = int(raw_since)
    except (TypeError, ValueError):
        since = 0
    queue = hub.subscribe(since_seq=since)

    def gen():
        try:
            yield "retry: 2000\n\n"
            last_keepalive = time.time()
            while True:
                drained = False
                while queue:
                    ev = queue.popleft()
                    payload = json.dumps(ev, default=str)
                    yield f"id: {ev['seq']}\nevent: {ev.get('type','log')}\ndata: {payload}\n\n"
                    drained = True
                if not drained:
                    if time.time() - last_keepalive > 15:
                        yield ": keepalive\n\n"
                        last_keepalive = time.time()
                    time.sleep(0.25)
        finally:
            hub.unsubscribe(queue)

    response = StreamingHttpResponse(gen(), content_type="text/event-stream")
    response["Cache-Control"] = "no-cache"
    response["X-Accel-Buffering"] = "no"
    return response


# ---------------------------------------------------------------------------
# Screen 3 - Verification + cleanup
# ---------------------------------------------------------------------------

@otp_required(login_url="migrator:login")
def verification(request: HttpRequest, migration_id: int) -> HttpResponse:
    migration = get_object_or_404(_editable_migrations(request.user), pk=migration_id)
    report = getattr(migration, "verification", None)

    folder_rows = []
    if report:
        for src, info in sorted(report.folders_json.items()):
            folder_rows.append({
                "src": src,
                "destination": info.get("destination", ""),
                "old_count": info.get("old_count", 0),
                "new_count": info.get("new_count", 0),
                "missing_count": info.get("missing_count", 0),
                "ok": info.get("missing_count", 0) == 0,
                "sample_missing": info.get("sample_missing", []),
            })

    gate = CleanupGate(migration, confirmed=False)
    gate.evaluate()
    age_min = None
    if report:
        age_min = int((timezone.now() - report.created_at).total_seconds() // 60)

    return render(request, "migrator/verification.html", {
        "migration": migration,
        "report": report,
        "folder_rows": folder_rows,
        "safety_results": gate.results,
        "age_min": age_min,
        "has_creds": bool(load_credentials(migration_id)),
        "nav_active": "migrations",
    })


def _safe_label(migration: Migration) -> str:
    raw = migration.name or migration.old_username or f"migration-{migration.pk}"
    return re.sub(r"[^A-Za-z0-9._-]+", "_", raw).strip("_") or f"migration-{migration.pk}"


@otp_required(login_url="migrator:login")
@require_GET
def download_backup(request: HttpRequest, migration_id: int) -> HttpResponse:
    """Stream a ZIP of one .mbox file per folder, built from MessageRecord.raw_bytes."""
    migration = get_object_or_404(_editable_migrations(request.user), pk=migration_id)

    folders_in_db = list(
        MessageRecord.objects.filter(migration=migration, backed_up=True)
        .exclude(raw_bytes=b"")
        .values_list("folder", flat=True)
        .distinct()
    )
    if not folders_in_db:
        raise Http404("No backup data for this migration. Run Backup first.")

    tmp = tempfile.NamedTemporaryFile(prefix=f"mailbox-{migration.pk}-", suffix=".zip", delete=False)
    try:
        with zipfile.ZipFile(tmp, "w", zipfile.ZIP_DEFLATED) as zf:
            for folder in folders_in_db:
                fname = re.sub(r"[^A-Za-z0-9._-]+", "_", folder).strip("_") + ".mbox"
                rows = MessageRecord.objects.filter(
                    migration=migration, folder=folder, backed_up=True,
                ).exclude(raw_bytes=b"").values_list("raw_bytes", flat=True)
                # mbox "From " separator between messages; rfc4155 short form.
                parts = []
                for raw in rows:
                    parts.append(b"From MAILER-DAEMON Thu Jan  1 00:00:00 1970\n")
                    parts.append(bytes(raw))
                    if not bytes(raw).endswith(b"\n"):
                        parts.append(b"\n")
                zf.writestr(fname, b"".join(parts))
    finally:
        tmp.close()

    filename = f"{_safe_label(migration)}-backup.zip"
    return FileResponse(open(tmp.name, "rb"), as_attachment=True, filename=filename)


def _duration_str(start, finish) -> str | None:
    if not (start and finish):
        return None
    secs = int((finish - start).total_seconds())
    h, rem = divmod(secs, 3600)
    m, s = divmod(rem, 60)
    if h:
        return f"{h}h {m}m {s}s"
    if m:
        return f"{m}m {s}s"
    return f"{s}s"


def _build_report_context(migration: Migration) -> dict:
    """Gather everything the Report screen and PDF render from a Migration."""
    phases = _phase_summary(migration)

    counts_by_folder = {
        row["folder"]: row
        for row in MessageRecord.objects.filter(migration=migration)
        .values("folder")
        .annotate(
            backed_up_n=Count("id", filter=Q(backed_up=True)),
            transferred_n=Count("id", filter=Q(transferred=True)),
        )
    }

    verify_report = getattr(migration, "verification", None)
    verify_by_folder: dict[str, dict] = (
        dict(verify_report.folders_json) if verify_report else {}
    )

    mappings = list(
        migration.folder_mappings
        .exclude(action=FolderMapping.ACTION_SKIP)
        .order_by("old_folder")
    )
    folder_rows = []
    for m in mappings:
        c = counts_by_folder.get(m.old_folder, {})
        v = verify_by_folder.get(m.old_folder, {})
        backed = c.get("backed_up_n", 0)
        transferred = c.get("transferred_n", 0)
        missing = v.get("missing_count", 0)
        sample_missing = list(v.get("sample_missing") or [])
        folder_rows.append({
            "src": m.old_folder,
            "dst": m.new_folder or m.old_folder,
            "backed_up": backed,
            "transferred": transferred,
            "missing": missing,
            # Counts seen live on each server when Verify ran. They can differ
            # from backed_up/transferred, which record what the run did earlier:
            # mail arriving (or being deleted into Trash) in between shows up
            # here and nowhere else.
            "verify_old": v.get("old_count", 0),
            "verify_new": v.get("new_count", 0),
            "sample_missing": sample_missing,
            "has_synthetic_missing": any(str(x).startswith("sha256-") for x in sample_missing),
            "verified": bool(v),
            "ok": bool(v) and missing == 0 and transferred >= backed and backed > 0,
        })

    totals = {
        "backed_up": MessageRecord.objects.filter(migration=migration, backed_up=True).count(),
        "transferred": MessageRecord.objects.filter(migration=migration, transferred=True).count(),
        "missing": verify_report.missing_total if verify_report else 0,
        "deleted": phases["cleanup"]["processed"] if phases["cleanup"]["status"] == PhaseRun.STATUS_SUCCESS else 0,
    }

    for p in phases.values():
        p["duration"] = _duration_str(p["started"], p["finished"])

    # Phases a restart cut short: still marked running with nothing behind them
    # (stalled), or already closed as interrupted by the recovery sweep. Both
    # get a Resume button, because this is the screen where a run that stopped
    # moving is noticed. Cleanup is excluded — it deletes mail, and needs the
    # verification report and the confirmation box, not a one-click restart.
    interrupted_phases = [
        {
            "phase": key,
            "label": dict(PhaseRun.PHASE_CHOICES).get(key, key.title()),
            "stalled": p["stalled"],
            "last_seen": migration.phase_runs.filter(phase=key).order_by("-id").first().last_sign_of_life,
        }
        for key, p in phases.items()
        if (p["stalled"] or p["interrupted"]) and key != PhaseRun.PHASE_CLEANUP
    ]

    overall_status = _overall_status(phases)

    return {
        "migration": migration,
        "phases": phases,
        "folder_rows": folder_rows,
        "totals": totals,
        "overall_status": overall_status,
        "interrupted_phases": interrupted_phases,
        "verify_report": verify_report,
    }


@otp_required(login_url="migrator:login")
def report(request: HttpRequest, migration_id: int) -> HttpResponse:
    """Read-only summary of everything that happened on this migration:
    phase timeline, totals, per-folder counts. No actions, no live updates."""
    migration = get_object_or_404(_user_migrations(request.user), pk=migration_id)
    return render(request, "migrator/report.html", {
        **_build_report_context(migration),
        "nav_active": "migrations",
        "is_admin_view": _is_admin(request.user),
    })


@otp_required(login_url="migrator:login")
@require_GET
def download_report_pdf(request: HttpRequest, migration_id: int) -> HttpResponse:
    """Render the Report screen as a downloadable PDF."""
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
    from reportlab.lib.units import mm
    from reportlab.platypus import (
        Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle,
    )

    migration = get_object_or_404(_user_migrations(request.user), pk=migration_id)
    ctx = _build_report_context(migration)
    phases = ctx["phases"]
    totals = ctx["totals"]
    folder_rows = ctx["folder_rows"]
    verify_report = ctx["verify_report"]
    overall_status = ctx["overall_status"]

    # Monochrome palette — the report PDF is intentionally black-and-white,
    # with greys used in place of any accent colors. Status differentiation
    # comes from emphasis (bold vs normal) rather than hue.
    BLACK = colors.HexColor("#000000")
    TEXT = colors.HexColor("#111111")
    MUTED = colors.HexColor("#555555")
    BORDER = colors.HexColor("#999999")
    RULE = colors.HexColor("#cccccc")
    LIGHT_BG = colors.HexColor("#eeeeee")
    PILL_BG = colors.HexColor("#e0e0e0")
    PILL_BG_STRONG = colors.HexColor("#cfcfcf")

    # Both 'foreground' and 'background' collapse to greyscale. Successful
    # states get the stronger pill background so they still read as the
    # "completed" tier without relying on color.
    STATUS_COLORS = {
        "complete":    (BLACK, PILL_BG_STRONG),
        "verified":    (BLACK, PILL_BG_STRONG),
        "transferred": (BLACK, PILL_BG),
        "backed-up":   (MUTED, PILL_BG),
        "in-progress": (BLACK, PILL_BG),
        "interrupted": (BLACK, PILL_BG),
        "not-started": (MUTED, PILL_BG),
        "success":     (BLACK, PILL_BG_STRONG),
        "failed":      (BLACK, PILL_BG_STRONG),
        "running":     (BLACK, PILL_BG),
        "pending":     (MUTED, PILL_BG),
    }

    buf = io.BytesIO()
    doc = SimpleDocTemplate(
        buf, pagesize=A4,
        leftMargin=18 * mm, rightMargin=18 * mm,
        topMargin=16 * mm, bottomMargin=16 * mm,
        title=f"Migration #{migration.pk} report",
        author="Mailbox Transfer",
    )

    styles = getSampleStyleSheet()
    h1 = ParagraphStyle(
        "H1", parent=styles["Heading1"], fontSize=20, leading=24,
        textColor=BLACK, spaceAfter=2,
    )
    sub = ParagraphStyle(
        "Sub", parent=styles["BodyText"], fontSize=10.5, leading=14,
        textColor=MUTED, spaceAfter=12,
    )
    section = ParagraphStyle(
        "Section", parent=styles["Heading3"], fontSize=12, leading=16,
        textColor=BLACK, spaceBefore=10, spaceAfter=6,
    )
    label = ParagraphStyle(
        "Label", parent=styles["BodyText"], fontSize=8, leading=10,
        textColor=MUTED,
        fontName="Helvetica-Bold", spaceAfter=2,
    )
    value = ParagraphStyle(
        "Value", parent=styles["BodyText"], fontSize=10, leading=13,
        textColor=TEXT,
    )
    stat_num = ParagraphStyle(
        "Stat", parent=styles["BodyText"], fontSize=18, leading=22,
        fontName="Helvetica-Bold", textColor=BLACK,
    )

    story = []

    fg, bg = STATUS_COLORS.get(overall_status, STATUS_COLORS["not-started"])
    title_tbl = Table(
        [[Paragraph("Report", h1),
          Paragraph(f'<font color="{fg.hexval()}">{overall_status.upper()}</font>', value)]],
        colWidths=[None, 90],
    )
    title_tbl.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("BACKGROUND", (1, 0), (1, 0), bg),
        ("BOX", (1, 0), (1, 0), 0.5, bg),
        ("ALIGN", (1, 0), (1, 0), "CENTER"),
        ("LEFTPADDING", (0, 0), (0, 0), 0),
        ("RIGHTPADDING", (0, 0), (0, 0), 0),
    ]))
    story.append(title_tbl)
    story.append(Paragraph("Everything that's happened on this migration so far.", sub))

    def kv(lbl: str, val_para):
        return [Paragraph(lbl.upper(), label), val_para]

    # Owner is shown to admins only; for owner == requester, the field is
    # redundant. The PDF view doesn't know which user is requesting (yet),
    # so include it whenever an owner is recorded — admins benefit, and for
    # regular users seeing their own name in their PDF is harmless.
    meta_rows = [
        [kv("Label", Paragraph(
            f"<b>{migration.name or '—'}</b> &middot; #{migration.id}", value)),
         kv("Created", Paragraph(
             migration.created_at.strftime("%Y-%m-%d %H:%M"), value))],
        [kv("Source", Paragraph(
            f"{migration.old_username}<br/>"
            f'<font size="8" color="#555555">{migration.old_host}:{migration.old_port}</font>',
            value)),
         kv("Destination", Paragraph(
             f"{migration.new_username}<br/>"
             f'<font size="8" color="#555555">{migration.new_host}:{migration.new_port}</font>',
             value))],
    ]
    if migration.owner_id:
        owner_html = f"<b>{migration.owner.get_username()}</b>"
        if migration.owner.email:
            owner_html += (
                f'<br/><font size="8" color="#555555">{migration.owner.email}</font>'
            )
        meta_rows.append([
            kv("Owner", Paragraph(owner_html, value)),
            kv("", Paragraph("", value)),
        ])
    meta = Table(meta_rows, colWidths=[None, None])
    meta.setStyle(TableStyle([
        ("BOX", (0, 0), (-1, -1), 0.5, BORDER),
        ("INNERGRID", (0, 0), (-1, -1), 0.5, RULE),
        ("LEFTPADDING", (0, 0), (-1, -1), 10),
        ("RIGHTPADDING", (0, 0), (-1, -1), 10),
        ("TOPPADDING", (0, 0), (-1, -1), 8),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
    ]))
    story.append(meta)
    story.append(Spacer(1, 10))

    def stat_cell(lbl: str, n: int, tone: str = "default"):
        # In greyscale, "green" / "red" emphasis becomes solid black; "muted"
        # values fade to mid-grey. Keeps the visual hierarchy without color.
        tones = {
            "green":   BLACK,
            "red":     BLACK,
            "muted":   MUTED,
            "default": BLACK,
        }
        num_style = ParagraphStyle(
            "StatN", parent=stat_num, textColor=tones.get(tone, tones["default"]),
        )
        return [Paragraph(lbl.upper(), label), Paragraph(str(n), num_style)]

    stats = Table(
        [[
            stat_cell("Backed up",   totals["backed_up"],   "green" if totals["backed_up"] else "muted"),
            stat_cell("Transferred", totals["transferred"], "green" if totals["transferred"] else "muted"),
            stat_cell("Missing",     totals["missing"],     "red"   if totals["missing"]     else "muted"),
            stat_cell("Deleted from source", totals["deleted"], "red" if totals["deleted"] else "muted"),
        ]],
        colWidths=[None, None, None, None],
    )
    stats.setStyle(TableStyle([
        ("BOX", (0, 0), (-1, -1), 0.5, BORDER),
        ("INNERGRID", (0, 0), (-1, -1), 0.5, BORDER),
        ("LEFTPADDING", (0, 0), (-1, -1), 10),
        ("RIGHTPADDING", (0, 0), (-1, -1), 10),
        ("TOPPADDING", (0, 0), (-1, -1), 10),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 10),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
    ]))
    story.append(stats)

    story.append(Paragraph("Phase timeline", section))

    def phase_row(n: int, name: str, count_txt: str, count_sub: str, s: dict):
        when = "not started"
        if s["started"]:
            start = s["started"].strftime("%Y-%m-%d %H:%M")
            if s["finished"]:
                when = f"{start} → {s['finished'].strftime('%H:%M:%S')} · {s.get('duration') or ''}".strip(" ·")
            else:
                when = f"{start} → running…"
        fg2, bg2 = STATUS_COLORS.get(s["status"], STATUS_COLORS["pending"])
        status_para = Paragraph(
            f'<font color="{fg2.hexval()}"><b>{(s["status"] or "pending").capitalize()}</b></font>',
            value,
        )
        return [
            str(n),
            [Paragraph(f"<b>{name}</b>", value),
             Paragraph(f'<font color="#555555" size="8.5">{when}</font>', value)],
            [Paragraph(f"<b>{count_txt}</b>", value),
             Paragraph(f'<font color="#555555" size="8.5">{count_sub}</font>', value)],
            status_para,
        ], bg2

    rows = []
    row_bgs = []
    p = phases["backup"]
    r, bg2 = phase_row(
        1, "Backup",
        f"{p['processed']} / {p['total']}" if p["total"] else "—",
        "messages downloaded", p,
    )
    rows.append(r); row_bgs.append(bg2)

    p = phases["transfer"]
    r, bg2 = phase_row(
        2, "Transfer",
        f"{p['processed']} / {p['total']}" if p["total"] else "—",
        "messages uploaded", p,
    )
    rows.append(r); row_bgs.append(bg2)

    p = phases["verify"]
    r, bg2 = phase_row(
        3, "Verify",
        f"{totals['missing']} missing" if verify_report else "—",
        f"of {verify_report.total_old} on source" if verify_report else "no report yet",
        p,
    )
    rows.append(r); row_bgs.append(bg2)

    p = phases["cleanup"]
    r, bg2 = phase_row(
        4, "Cleanup",
        str(p["processed"]) if p["status"] == PhaseRun.STATUS_SUCCESS else "—",
        "deleted from source", p,
    )
    rows.append(r); row_bgs.append(bg2)

    timeline = Table(rows, colWidths=[16, None, 150, 70])
    style_cmds = [
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("ALIGN", (0, 0), (0, -1), "CENTER"),
        ("ALIGN", (2, 0), (2, -1), "RIGHT"),
        ("ALIGN", (3, 0), (3, -1), "CENTER"),
        ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
        ("TEXTCOLOR", (0, 0), (0, -1), BLACK),
        ("BOX", (0, 0), (0, -1), 0.5, BORDER),
        ("BOX", (0, 0), (-1, -1), 0.5, BORDER),
        ("LINEBELOW", (0, 0), (-1, -2), 0.5, RULE),
        ("LEFTPADDING", (0, 0), (-1, -1), 8),
        ("RIGHTPADDING", (0, 0), (-1, -1), 8),
        ("TOPPADDING", (0, 0), (-1, -1), 8),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
    ]
    # Step number cell gets a light-grey fill so it still reads as a chip,
    # without depending on color.
    for i in range(len(row_bgs)):
        style_cmds.append(("BACKGROUND", (0, i), (0, i), LIGHT_BG))
    timeline.setStyle(TableStyle(style_cmds))
    story.append(timeline)

    story.append(Paragraph(
        f"Per-folder breakdown <font color='#555555' size='9'>· {len(folder_rows)} folder(s)</font>",
        section,
    ))

    if folder_rows:
        story.append(Paragraph(
            "<font color='#555555' size='8'>Backed up and Transferred show what the last run copied. "
            "On source and On dest. show how many messages each server had when Verify last ran.</font>",
            value,
        ))
        story.append(Spacer(1, 4))
        head = [
            Paragraph("<b>Source folder</b>", value),
            Paragraph("<b>Destination</b>", value),
            Paragraph("<b>Backed up</b>", value),
            Paragraph("<b>Transferred</b>", value),
            Paragraph("<b>On source</b><br/><font size='7' color='#555555'>at verify</font>", value),
            Paragraph("<b>On dest.</b><br/><font size='7' color='#555555'>at verify</font>", value),
            Paragraph("<b>Missing</b>", value),
            Paragraph("<b>Status</b>", value),
        ]
        body = []
        for r in folder_rows:
            # Status hierarchy in greyscale: bold-black = success/failure
            # signal, normal-grey = intermediate, light-grey = idle.
            if r["ok"]:
                status_html = '<font color="#000000"><b>Verified</b></font>'
            elif r["missing"]:
                status_html = f'<font color="#000000"><b>{r["missing"]} missing</b></font>'
            elif r["transferred"]:
                status_html = '<font color="#333333">Transferred</font>'
            elif r["backed_up"]:
                status_html = '<font color="#333333">Backed up</font>'
            else:
                status_html = '<font color="#888888">Pending</font>'
            missing_txt = str(r["missing"]) if r["verified"] else "—"
            verify_old_txt = str(r["verify_old"]) if r["verified"] else "—"
            verify_new_txt = str(r["verify_new"]) if r["verified"] else "—"
            body.append([
                Paragraph(f"<b>{r['src']}</b>", value),
                Paragraph(f'<font color="#555555">{r["dst"]}</font>', value),
                Paragraph(str(r["backed_up"]), value),
                Paragraph(str(r["transferred"]), value),
                Paragraph(verify_old_txt, value),
                Paragraph(verify_new_txt, value),
                Paragraph(missing_txt, value),
                Paragraph(status_html, value),
            ])
        folders = Table(
            [head] + body,
            colWidths=[None, None, 50, 52, 46, 46, 42, 62],
            repeatRows=1,
        )
        folders.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), LIGHT_BG),
            ("BOX", (0, 0), (-1, -1), 0.5, BORDER),
            ("LINEBELOW", (0, 0), (-1, 0), 0.5, BORDER),
            ("INNERGRID", (0, 1), (-1, -1), 0.25, RULE),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("ALIGN", (2, 0), (6, -1), "RIGHT"),
            ("LEFTPADDING", (0, 0), (-1, -1), 6),
            ("RIGHTPADDING", (0, 0), (-1, -1), 6),
            ("TOPPADDING", (0, 0), (-1, -1), 6),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ]))
        story.append(folders)
    else:
        story.append(Paragraph(
            '<font color="#555555">No active folder mappings yet.</font>', value,
        ))

    doc.build(story)
    buf.seek(0)
    filename = f"{_safe_label(migration)}-report.pdf"
    return FileResponse(buf, as_attachment=True, filename=filename, content_type="application/pdf")


@otp_required(login_url="migrator:login")
@require_POST
def delete_migration(request: HttpRequest, migration_id: int) -> HttpResponse:
    migration = get_object_or_404(_editable_migrations(request.user), pk=migration_id)
    migration.delete()
    STATE.set_credentials(migration_id, Credentials())
    return redirect("migrator:index")


# ---------------------------------------------------------------------------
# Backups — standalone, backup-only mailbox archives (available to every user)
#
# A BackupJob has no destination server and never writes to a mailbox. Jobs are
# private to their owner: mail content is never exposed to another account,
# admins included.
# ---------------------------------------------------------------------------

def _owned_backup_jobs(user):
    if not (user and user.is_authenticated):
        return BackupJob.objects.none()
    return BackupJob.objects.filter(owner=user)


def _visible_backup_jobs(user):
    """Jobs LISTED for `user` — everyone's for an admin, own only otherwise."""
    if _is_admin(user):
        return BackupJob.objects.all()
    return _owned_backup_jobs(user)


def _editable_backup_jobs(user):
    """Jobs the user can ACT on (open, run, schedule, download, delete).

    Admins can act on every job, not only their own, for the same reason as
    `_editable_migrations`: they run this service and a stuck mailbox belonging
    to a user who has gone home is theirs to fix. It does mean an admin can
    download and delete another user's archived mail, so the delete
    confirmation names the owner.
    """
    if _is_admin(user):
        return BackupJob.objects.all()
    return _owned_backup_jobs(user)


# Backup and restore jobs describe one run, not a ladder of phases, so they get
# their own five states. Ordered least-far-along first, like STATUS_RANK.
JOB_STATES = [
    ("not-run", "Not run"),
    ("interrupted", "Interrupted"),
    ("running", "Running"),
    ("failed", "Failed"),
    ("complete", "Complete"),
]


def _job_state(job) -> str:
    """The one word describing a backup or restore job's latest run.

    Shared by both lists so the badge, the filter and the counts can't
    disagree. `interrupted` beats `running` because a stalled job is marked
    running but its process is gone; `complete` wins outright because
    `interrupted` is cleared at the start of every run.
    """
    if job.status == "success":
        return "complete"
    if job.is_stalled or job.interrupted:
        return "interrupted"
    if job.status == "running":
        return "running"
    if job.status == "failed":
        return "failed"
    return "not-run"


# JOB_STATES is ordered least-far-along first, so its position is the rank a
# status sort wants: alphabetical would put "complete" above "running" and tell
# nobody anything.
JOB_STATE_RANK = {state: i for i, (state, _label) in enumerate(JOB_STATES)}

def _owner_key(job) -> str:
    return _text_key(job.owner.get_username() if job.owner_id else "")


BACKUP_SORTS = {
    "created": lambda j: j.created_at,
    "mailbox": lambda j: _text_key(j.name or j.username),
    "owner": _owner_key,
    "status": lambda j: JOB_STATE_RANK[j.state],
    # Manual-only backups rank below scheduled ones, and the scheduled ones go
    # by how soon they next run.
    "schedule": lambda j: (j.schedule_is_on, j.next_run_at or _FOREVER),
    "messages": lambda j: j.message_count,
    "attachments": lambda j: j.attachment_count,
    "size": lambda j: j.storage_bytes,
    "last_run": lambda j: j.finished_at or _LONG_AGO,
}

RESTORE_SORTS = {
    "created": lambda j: j.created_at,
    "destination": lambda j: _text_key(j.name or j.username),
    "owner": _owner_key,
    "source": lambda j: _text_key(j.source_label),
    "status": lambda j: JOB_STATE_RANK[j.state],
    "imported": lambda j: j.imported,
    "skipped": lambda j: j.skipped,
    "finished": lambda j: j.finished_at or _LONG_AGO,
}

# Columns where a first click should mean biggest, newest or busiest first.
JOB_SORTS_DESC_FIRST = frozenset({
    "created", "schedule", "messages", "attachments", "size", "last_run",
    "imported", "skipped", "finished",
})


def _list_keep(ctx: dict) -> dict:
    """The sort, filter and search a pager link has to carry over."""
    return {
        k: v for k, v in (
            ("sort", ctx["sort"]), ("dir", ctx["dir"]),
            ("status", ctx["status_filter"]), ("q", ctx["search"]),
        ) if v
    }


def _job_list_context(request, base_qs, search_fields, sorts, default_sort="created"):
    """Search + status-filter one job list. -> (jobs, context fragment).

    The counts are taken from the search results but before the status filter,
    so the dropdown shows what each option would give you. The sort itself is
    left to `_sort_jobs`, which the view calls once its rows are decorated.
    """
    search = request.GET.get("q", "").strip()
    wanted = request.GET.get("status", "")
    if wanted not in dict(JOB_STATES):
        wanted = ""
    sort = request.GET.get("sort", default_sort)
    if sort not in sorts:
        sort = default_sort
    direction = "asc" if request.GET.get("dir") == "asc" else "desc"

    all_count = base_qs.count()
    if search:
        matches = Q()
        for field in search_fields:
            matches |= Q(**{f"{field}__icontains": search})
        base_qs = base_qs.filter(matches)

    labels = dict(JOB_STATES)
    jobs = list(base_qs)
    for job in jobs:
        job.state = _job_state(job)
        job.state_label = labels[job.state]

    counts: dict[str, int] = {}
    for job in jobs:
        counts[job.state] = counts.get(job.state, 0) + 1
    total = len(jobs)

    unfiltered = jobs
    if wanted:
        jobs = [j for j in jobs if j.state == wanted]

    return jobs, unfiltered, {
        "search": search,
        "status_filter": wanted,
        "sort": sort,
        "dir": direction,
        "sortcols": _sort_links(
            sorts, sort, direction,
            {**{k: v for k, v in (("status", wanted), ("q", search)) if v},
             "per": _page_size(request)},
            desc_first=JOB_SORTS_DESC_FIRST,
        ),
        "status_choices": [
            {"value": v, "label": label, "count": counts.get(v, 0)}
            for v, label in JOB_STATES
        ],
        "total_count": total,
        "all_count": all_count,
        "shown_count": len(jobs),
    }


@otp_required(login_url="migrator:login")
def backups(request: HttpRequest) -> HttpResponse:
    """List backup jobs with their size on disk — own only, or all for admins."""
    jobs, all_jobs, list_ctx = _job_list_context(
        request,
        _visible_backup_jobs(request.user).select_related("owner"),
        ["name", "username", "host", "owner__username"],
        BACKUP_SORTS,
    )
    # Admins act on every row; everyone else only ever sees their own.
    can_manage_all = _is_admin(request.user)
    for job in jobs:
        job.can_manage = can_manage_all or job.owner_id == request.user.id

    from django.db.models import Sum
    stored_by_job: dict[int, dict] = {}
    if jobs:
        for row in (
            BackupMessage.objects.filter(job__in=jobs)
            .values("job")
            .annotate(n=Count("id"), size=Sum("size"), atts=Sum("attachment_count"))
        ):
            stored_by_job[row["job"]] = row
    for job in jobs:
        row = stored_by_job.get(job.id, {})
        job.message_count = row.get("n", 0)
        job.attachment_count = row.get("atts") or 0
        job.storage_bytes = row.get("size") or 0     # the Size column sorts on this
        job.storage_display = _humanize_bytes(job.storage_bytes)

    # Last, so the size and count keys have something to read.
    _sort_rows(jobs, BACKUP_SORTS, list_ctx["sort"], list_ctx["dir"])
    pager = _paginate(request, jobs, _list_keep(list_ctx))

    from .scheduler import health
    return render(request, "migrator/backups.html", {
        "jobs": pager["page_obj"].object_list,
        "scheduler": health(),
        "any_scheduled": any(j.schedule_is_on for j in all_jobs),
        "is_admin_view": _is_admin(request.user),
        "nav_active": "backups",
        **list_ctx,
        **pager,
    })


@otp_required(login_url="migrator:login")
def backup_config(request: HttpRequest, job_id: int | None = None) -> HttpResponse:
    """Create or edit a backup job's mailbox connection."""
    job = get_object_or_404(_editable_backup_jobs(request.user), pk=job_id) if job_id else None

    if request.method == "POST":
        form = BackupJobForm(request.POST, instance=job)
        if form.is_valid():
            obj = form.save(commit=False)
            if obj.owner_id is None:
                obj.owner = request.user
            obj.save()
            password = form.cleaned_data.get("password") or ""
            if not password and not bytes(obj.password_enc):
                # Left blank on a mailbox this user has already given us a
                # password for: reuse it rather than saving a job that cannot
                # log in.
                password = recall_password(obj.owner_id, obj.host, obj.username)
            if password:
                obj.password_enc = encrypt(password)
                obj.save(update_fields=["password_enc"])
                remember_password(obj.owner_id, obj.host, obj.username, password)
            messages.success(request, "Mailbox saved.")
            return redirect("migrator:backup_detail", job_id=obj.pk)
    else:
        form = BackupJobForm(instance=job)

    return render(request, "migrator/backup_config.html", {
        "form": form,
        "job": job,
        "nav_active": "backups",
    })


@otp_required(login_url="migrator:login")
def backup_detail(request: HttpRequest, job_id: int) -> HttpResponse:
    """Folder picker, run controls, live log and download for one backup job."""
    from .backup import job_stats

    job = get_object_or_404(_editable_backup_jobs(request.user), pk=job_id)

    from django.db.models import Sum
    stored_by_folder = {
        row["folder"]: row
        for row in (
            BackupMessage.objects.filter(job=job)
            .values("folder")
            .annotate(n=Count("id"), size=Sum("size"), atts=Sum("attachment_count"))
        )
    }
    folders = []
    for f in job.folders.all():
        row = stored_by_folder.get(f.name, {})
        folders.append({
            "id": f.id,
            "name": f.name,
            "selected": f.selected,
            "server_count": f.server_count,
            "stored": row.get("n", 0),
            "attachments": row.get("atts") or 0,
            "size_display": _humanize_bytes(row.get("size") or 0),
        })

    stats = job_stats(job)
    stats["size_display"] = _humanize_bytes(stats["bytes"])

    from .scheduler import health
    return render(request, "migrator/backup_detail.html", {
        "job": job,
        "folders": folders,
        "selected_count": sum(1 for f in folders if f["selected"]),
        "stats": stats,
        "has_password": bool(bytes(job.password_enc)),
        "duration": _duration_str(job.started_at, job.finished_at),
        "schedule_form": BackupScheduleForm(instance=job),
        "scheduler": health(),
        "tz_name": timezone.get_current_timezone_name(),
        "nav_active": "backups",
    })


@otp_required(login_url="migrator:login")
@require_POST
def backup_schedule(request: HttpRequest, job_id: int) -> HttpResponse:
    """Save how often this mailbox backs itself up, and recompute its next run."""
    from .scheduler import reschedule

    job = get_object_or_404(_editable_backup_jobs(request.user), pk=job_id)
    form = BackupScheduleForm(request.POST, instance=job)
    if not form.is_valid():
        messages.error(request, "Could not save the schedule — check the fields.")
        return redirect("migrator:backup_detail", job_id=job.pk)

    job = form.save()
    next_run = reschedule(job)
    if not job.schedule_is_on:
        messages.success(request, "Automatic backups turned off. You can still run it by hand.")
    elif next_run:
        messages.success(
            request,
            f"{job.schedule_description()}. Next run "
            f"{timezone.localtime(next_run):%Y-%m-%d %H:%M}.",
        )
    return redirect("migrator:backup_detail", job_id=job.pk)


@otp_required(login_url="migrator:login")
@require_POST
def backup_refresh_folders(request: HttpRequest, job_id: int) -> JsonResponse:
    """Connect to the mailbox and (re)discover its folder list."""
    from .backup import refresh_folders

    job = get_object_or_404(_editable_backup_jobs(request.user), pk=job_id)
    try:
        rows = refresh_folders(job)
    except Exception as exc:
        return JsonResponse({"ok": False, "error": str(exc)}, status=400)
    return JsonResponse({
        "ok": True,
        "count": len(rows),
        "folders": [
            {"name": f.name, "selected": f.selected, "server_count": f.server_count}
            for f in rows
        ],
    })


@otp_required(login_url="migrator:login")
@require_POST
def backup_save_folders(request: HttpRequest, job_id: int) -> JsonResponse:
    """Persist which folders the next run should download."""
    job = get_object_or_404(_editable_backup_jobs(request.user), pk=job_id)
    try:
        names = json.loads(request.POST.get("selected", "[]"))
    except json.JSONDecodeError:
        return JsonResponse({"ok": False, "error": "Bad payload"}, status=400)
    if not isinstance(names, list):
        return JsonResponse({"ok": False, "error": "Bad payload"}, status=400)

    wanted = {str(n) for n in names}
    with transaction.atomic():
        job.folders.filter(name__in=wanted).update(selected=True)
        job.folders.exclude(name__in=wanted).update(selected=False)
    return JsonResponse({"ok": True, "selected": len(wanted)})


@otp_required(login_url="migrator:login")
@require_POST
def backup_start(request: HttpRequest, job_id: int) -> JsonResponse:
    from .backup import blocking_reason, launch_backup_job

    job = get_object_or_404(_editable_backup_jobs(request.user), pk=job_id)
    reason = blocking_reason(job)
    if reason == "no password saved":
        return JsonResponse(
            {"ok": False, "error": "No password saved for this mailbox. Edit it and enter the password again."},
            status=400,
        )
    if reason:
        return JsonResponse(
            {"ok": False, "error": "Select at least one folder to back up."},
            status=400,
        )
    started = launch_backup_job(job.pk)
    return JsonResponse({"ok": True, "started": started})


@otp_required(login_url="migrator:login")
@require_GET
def backup_status(request: HttpRequest, job_id: int) -> JsonResponse:
    job = get_object_or_404(_editable_backup_jobs(request.user), pk=job_id)
    return JsonResponse({
        "status": job.status,
        "processed": job.processed,
        "total": job.total,
        "error": job.error,
        "stalled": job.is_stalled,
        "started": job.started_at.isoformat() if job.started_at else None,
        "finished": job.finished_at.isoformat() if job.finished_at else None,
    })


@otp_required(login_url="migrator:login")
def backup_log_snapshot(request: HttpRequest, job_id: int) -> JsonResponse:
    from .backup import hub_key

    job = get_object_or_404(_editable_backup_jobs(request.user), pk=job_id)
    events, max_seq = STATE.hub(hub_key(job.pk)).snapshot()
    return JsonResponse({"events": events, "max_seq": max_seq})


@otp_required(login_url="migrator:login")
@csrf_exempt
def backup_stream(request: HttpRequest, job_id: int) -> StreamingHttpResponse:
    from .backup import hub_key

    job = get_object_or_404(_editable_backup_jobs(request.user), pk=job_id)
    return _sse_response(request, STATE.hub(hub_key(job.pk)))


@otp_required(login_url="migrator:login")
@require_GET
def backup_download(request: HttpRequest, job_id: int) -> HttpResponse:
    """Stream the archive: one folder tree of .eml files plus extracted
    attachments and a manifest."""
    from .backup import TempArchiveFile, archive_filename, build_archive

    job = get_object_or_404(_editable_backup_jobs(request.user), pk=job_id)
    if not BackupMessage.objects.filter(job=job).exclude(raw_bytes=b"").exists():
        raise Http404("Nothing archived yet for this mailbox. Run the backup first.")

    path = build_archive(job)
    return FileResponse(
        TempArchiveFile(path, "rb"), as_attachment=True,
        filename=archive_filename(job), content_type="application/zip",
    )


@otp_required(login_url="migrator:login")
@require_POST
def delete_backup_job(request: HttpRequest, job_id: int) -> HttpResponse:
    job = get_object_or_404(_editable_backup_jobs(request.user), pk=job_id)
    label = job.label
    job.delete()
    messages.success(request, f"Deleted backup “{label}” and its archived messages.")
    return redirect("migrator:backups")


# ---------------------------------------------------------------------------
# Restore — import an archive into a mailbox (the reverse of a backup)
#
# Like backups, restore jobs are private to their owner. The destination is the
# only server touched, and only ever with APPEND.
# ---------------------------------------------------------------------------

def _owned_restore_jobs(user):
    if not (user and user.is_authenticated):
        return RestoreJob.objects.none()
    return RestoreJob.objects.filter(owner=user)


def _visible_restore_jobs(user):
    """Imports LISTED for `user` — everyone's for an admin, own only otherwise."""
    if _is_admin(user):
        return RestoreJob.objects.all()
    return _owned_restore_jobs(user)


def _editable_restore_jobs(user):
    """Imports the user can ACT on. Admins can act on every one — see
    `_editable_backup_jobs` for why."""
    if _is_admin(user):
        return RestoreJob.objects.all()
    return _owned_restore_jobs(user)


@otp_required(login_url="migrator:login")
def restores(request: HttpRequest) -> HttpResponse:
    jobs, _all_jobs, list_ctx = _job_list_context(
        request,
        _visible_restore_jobs(request.user).select_related("source_backup", "owner"),
        ["name", "username", "host", "owner__username", "source_backup__name"],
        RESTORE_SORTS,
    )
    can_manage_all = _is_admin(request.user)
    for job in jobs:
        job.size_display = _humanize_bytes(job.archive_size)
        job.can_manage = can_manage_all or job.owner_id == request.user.id
    _sort_rows(jobs, RESTORE_SORTS, list_ctx["sort"], list_ctx["dir"])
    pager = _paginate(request, jobs, _list_keep(list_ctx))
    return render(request, "migrator/restores.html", {
        "jobs": pager["page_obj"].object_list,
        "is_admin_view": _is_admin(request.user),
        "nav_active": "restores",
        **list_ctx,
        **pager,
    })


@otp_required(login_url="migrator:login")
def restore_new(request: HttpRequest) -> HttpResponse:
    """Create an import: destination mailbox + where the messages come from."""
    from .restore import ArchiveError, ingest_archive, load_from_backup

    if request.method == "POST":
        form = RestoreJobForm(
            request.POST, request.FILES, user=request.user,
            backups=_editable_backup_jobs(request.user),
        )
        if form.is_valid():
            obj = form.save(commit=False)
            obj.owner = request.user
            obj.save()
            password = form.cleaned_data.get("password") or ""
            if not password:
                password = recall_password(obj.owner_id, obj.host, obj.username)
            if password:
                obj.password_enc = encrypt(password)
                obj.save(update_fields=["password_enc"])
                remember_password(obj.owner_id, obj.host, obj.username, password)

            try:
                if obj.source_kind == RestoreJob.SOURCE_BACKUP:
                    summary = load_from_backup(obj)
                else:
                    upload = form.cleaned_data["archive"]
                    summary = ingest_archive(obj, upload.read(), upload.name)
            except ArchiveError as exc:
                obj.delete()
                form.add_error("archive" if request.FILES else "source_backup", str(exc))
            except Exception as exc:
                obj.delete()
                form.add_error(None, f"Could not read that archive: {exc}")
            else:
                extra = (
                    f" ({summary['duplicates']} duplicate(s) ignored)"
                    if summary["duplicates"] else ""
                )
                messages.success(
                    request,
                    f"Read {summary['messages']} message(s) in "
                    f"{summary['folders']} folder(s){extra}.",
                )
                return redirect("migrator:restore_detail", job_id=obj.pk)
    else:
        form = RestoreJobForm(
            user=request.user, backups=_editable_backup_jobs(request.user),
        )

    backups_available = (
        _editable_backup_jobs(request.user)
        .filter(messages__isnull=False).distinct().exists()
    )
    return render(request, "migrator/restore_new.html", {
        "form": form,
        "backups_available": backups_available,
        "nav_active": "restores",
    })


@otp_required(login_url="migrator:login")
def restore_detail(request: HttpRequest, job_id: int) -> HttpResponse:
    job = get_object_or_404(_editable_restore_jobs(request.user), pk=job_id)
    folders = list(job.folders.all())
    return render(request, "migrator/restore_detail.html", {
        "job": job,
        "folders": folders,
        "active_count": sum(1 for f in folders if f.action != "skip"),
        "active_messages": sum(f.message_count for f in folders if f.action != "skip"),
        "has_password": bool(bytes(job.password_enc)),
        "duration": _duration_str(job.started_at, job.finished_at),
        "nav_active": "restores",
    })


@otp_required(login_url="migrator:login")
@require_POST
def restore_pair(request: HttpRequest, job_id: int) -> JsonResponse:
    """Connect to the destination and auto-pair the archive's folders."""
    from .restore import pair_folders

    job = get_object_or_404(_editable_restore_jobs(request.user), pk=job_id)
    try:
        rows = pair_folders(job)
    except Exception as exc:
        return JsonResponse({"ok": False, "error": str(exc)}, status=400)
    return JsonResponse({
        "ok": True,
        "rows": [
            {
                "source": r.source_folder, "dest": r.dest_folder,
                "action": r.action, "reason": r.pairing_reason,
                "count": r.message_count,
            }
            for r in rows
        ],
    })


@otp_required(login_url="migrator:login")
@require_POST
def restore_save_mapping(request: HttpRequest, job_id: int) -> JsonResponse:
    """Persist the edited folder mapping table."""
    job = get_object_or_404(_editable_restore_jobs(request.user), pk=job_id)
    try:
        rows = json.loads(request.POST.get("payload", "[]"))
    except json.JSONDecodeError:
        return JsonResponse({"ok": False, "error": "Bad payload"}, status=400)
    if not isinstance(rows, list):
        return JsonResponse({"ok": False, "error": "Bad payload"}, status=400)

    by_source = {f.source_folder: f for f in job.folders.all()}
    valid_actions = {"map", "create", "skip"}
    saved = 0
    with transaction.atomic():
        for row in rows:
            if not isinstance(row, dict):
                continue
            existing = by_source.get(row.get("source") or "")
            if existing is None:
                continue
            action = row.get("action") or "map"
            if action not in valid_actions:
                action = "map"
            existing.dest_folder = (row.get("dest") or "").strip()
            existing.action = action
            existing.pairing_reason = "manual"
            existing.save(update_fields=["dest_folder", "action", "pairing_reason"])
            saved += 1
    return JsonResponse({"ok": True, "saved": saved})


@otp_required(login_url="migrator:login")
@require_POST
def restore_start(request: HttpRequest, job_id: int) -> JsonResponse:
    from .restore import launch_restore_job

    job = get_object_or_404(_editable_restore_jobs(request.user), pk=job_id)
    if not bytes(job.password_enc):
        return JsonResponse(
            {"ok": False, "error": "No password saved for the destination mailbox."},
            status=400,
        )
    if not job.paired_at:
        # The UI disables the button until then; this covers a stale page.
        return JsonResponse(
            {"ok": False,
             "error": "Pair the archive's folders against the destination first."},
            status=400,
        )
    active = job.folders.exclude(action="skip")
    if not active.exists():
        return JsonResponse(
            {"ok": False, "error": "Every folder is set to skip — nothing to import."},
            status=400,
        )
    if active.filter(dest_folder="").exists():
        return JsonResponse(
            {"ok": False, "error": "Some folders have no destination. Fill them in or set them to skip."},
            status=400,
        )
    started = launch_restore_job(job.pk)
    return JsonResponse({"ok": True, "started": started})


@otp_required(login_url="migrator:login")
@require_GET
def restore_status(request: HttpRequest, job_id: int) -> JsonResponse:
    job = get_object_or_404(_editable_restore_jobs(request.user), pk=job_id)
    return JsonResponse({
        "status": job.status,
        "processed": job.processed,
        "total": job.total,
        "imported": job.imported,
        "skipped": job.skipped,
        "failed": job.failed,
        "error": job.error,
        "stalled": job.is_stalled,
    })


@otp_required(login_url="migrator:login")
def restore_log_snapshot(request: HttpRequest, job_id: int) -> JsonResponse:
    from .restore import hub_key

    job = get_object_or_404(_editable_restore_jobs(request.user), pk=job_id)
    events, max_seq = STATE.hub(hub_key(job.pk)).snapshot()
    return JsonResponse({"events": events, "max_seq": max_seq})


@otp_required(login_url="migrator:login")
@csrf_exempt
def restore_stream(request: HttpRequest, job_id: int) -> StreamingHttpResponse:
    from .restore import hub_key

    job = get_object_or_404(_editable_restore_jobs(request.user), pk=job_id)
    return _sse_response(request, STATE.hub(hub_key(job.pk)))


@otp_required(login_url="migrator:login")
@require_POST
def delete_restore_job(request: HttpRequest, job_id: int) -> HttpResponse:
    job = get_object_or_404(_editable_restore_jobs(request.user), pk=job_id)
    label = job.label
    job.delete()
    messages.success(request, f"Deleted import “{label}”. Imported mail stays in the mailbox.")
    return redirect("migrator:restores")


@otp_required(login_url="migrator:login")
@require_POST
def start_cleanup(request: HttpRequest, migration_id: int) -> HttpResponse:
    migration = get_object_or_404(_editable_migrations(request.user), pk=migration_id)
    confirmed = request.POST.get("confirm") == "yes"
    if not confirmed:
        return JsonResponse({"ok": False, "error": "Confirmation checkbox required"}, status=400)
    if not load_credentials(migration_id):
        return JsonResponse({"ok": False, "error": "No credentials saved for this migration"}, status=400)
    started = launch_phase(migration.pk, PhaseRun.PHASE_CLEANUP, confirmed=True)
    return JsonResponse({"ok": True, "started": started})
