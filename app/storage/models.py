"""Pydantic models for the file-based (no-DBMS) local storage layer.

Everything here is plain, human-readable JSON - see plan.md section 6 for the
full rationale (no SQLite/ORM, one directory per certificate under
``/app/data/certificates/{local_id}/``).
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Literal
from uuid import uuid4

from pydantic import BaseModel, Field

IdentityType = Literal["DNS", "IP"]


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class Identity(BaseModel):
    type: IdentityType
    value: str
    is_primary: bool = False


class CertificateMeta(BaseModel):
    """Corresponds to ``meta.json`` for a single managed certificate."""

    local_id: str = Field(default_factory=lambda: str(uuid4()))
    npm_certificate_id: int
    name: str
    provider: Literal["other"] = "other"
    identities: list[Identity] = Field(default_factory=list)
    renew_before_days: int = 30
    auto_renew: bool = True
    key_size: int = 2048
    key_type: Literal["rsa", "ecdsa"] = "rsa"

    cached_expires_at: str | None = None
    last_synced_at: str | None = None
    last_renewed_at: str | None = None
    last_renewal_status: Literal["ok", "failed", "pending"] | None = None
    last_renewal_error: str | None = None

    # Manual-reload workaround was intentionally removed - see plan.md 2.3/7.
    # The application only ever *shows a notice*, it never triggers a reload.
    reload_required: bool = False
    reload_required_since: str | None = None

    created_at: str = Field(default_factory=now_iso)
    updated_at: str = Field(default_factory=now_iso)

    def primary_identity(self) -> Identity | None:
        for identity in self.identities:
            if identity.is_primary:
                return identity
        return self.identities[0] if self.identities else None


class HistoryEntry(BaseModel):
    started_at: str
    finished_at: str | None = None
    status: Literal["success", "failed", "running"]
    trigger: Literal["scheduler", "manual"]
    old_expires_at: str | None = None
    new_expires_at: str | None = None
    error_message: str | None = None


class AppSettings(BaseModel):
    """Corresponds to ``settings.json`` (global, key/value-ish config)."""

    renew_before_days: int = 30
    check_interval_seconds: int = 21600
    key_size: int = 2048
    key_type: Literal["rsa", "ecdsa"] = "rsa"
