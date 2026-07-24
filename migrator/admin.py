from django.contrib import admin

from .models import (
    AccessEvent, FolderMapping, Migration, MessageRecord, PhaseRun, VerificationReport,
)


@admin.register(Migration)
class MigrationAdmin(admin.ModelAdmin):
    list_display = ("id", "name", "old_username", "new_username", "created_at")
    search_fields = ("name", "old_username", "new_username")


@admin.register(FolderMapping)
class FolderMappingAdmin(admin.ModelAdmin):
    list_display = ("migration", "old_folder", "new_folder", "action", "pairing_reason")
    list_filter = ("action", "pairing_reason")


@admin.register(PhaseRun)
class PhaseRunAdmin(admin.ModelAdmin):
    list_display = ("migration", "phase", "status", "processed", "total", "started_at", "finished_at")
    list_filter = ("phase", "status")


@admin.register(AccessEvent)
class AccessEventAdmin(admin.ModelAdmin):
    list_display = ("kind", "ip_address", "path", "email", "created_at", "seen")
    list_filter = ("kind", "seen")
    search_fields = ("ip_address", "email", "path")
    readonly_fields = ("kind", "ip_address", "path", "email", "user_agent", "created_at")


admin.site.register(MessageRecord)
admin.site.register(VerificationReport)
