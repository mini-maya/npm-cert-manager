"""Renewal orchestration - plan.md section 7, the full step-by-step
algorithm (expiry check -> key/CSR/cert generation -> pre-upload validation
-> NPM upload -> reload notice -> persistence), wired together with the
lockfile mechanism from app.storage.locking.

A failed renewal for one certificate must never abort processing of the
others (plan.md "Fehlerbehandlung") - callers should iterate certificates
and catch exceptions per-certificate, e.g. via `renew_if_due`.
"""
from __future__ import annotations

import datetime
import logging

from app.certificates.ca import CertificateAuthority
from app.certificates.generator import CertificateGenerationError, issue_certificate
from app.npm.client import NpmClient
from app.npm.errors import NpmError
from app.storage import repository as repo
from app.storage.locking import LockHeldError, renewal_lock
from app.storage.models import CertificateMeta, HistoryEntry, now_iso

logger = logging.getLogger("npm_cert_manager.renewal")


class RenewalSkipped(Exception):
    """Not an error - raised (and caught internally) when a renewal is not
    due yet or is already in progress elsewhere.
    """


def remaining_days(meta: CertificateMeta) -> int | None:
    if not meta.cached_expires_at:
        return None
    expires_at_raw = meta.cached_expires_at.replace("Z", "+00:00")
    expires_at = datetime.datetime.fromisoformat(expires_at_raw)
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=datetime.timezone.utc)
    now = datetime.datetime.now(datetime.timezone.utc)
    return (expires_at.astimezone(datetime.timezone.utc) - now).days


def is_renewal_due(meta: CertificateMeta) -> bool:
    days = remaining_days(meta)
    if days is None:
        # No known expiry yet (never synced) - treat conservatively as "due"
        # so it surfaces for a manual look rather than being silently skipped.
        return True
    return days <= meta.renew_before_days


def renew_certificate(
    local_id: str,
    client: NpmClient,
    ca: CertificateAuthority,
    trigger: str = "manual",
    force: bool = False,
    valid_days: int | None = None,
) -> CertificateMeta:
    """Executes one full renewal for a single certificate. Raises on
    failure (after persisting the failure to meta.json/history.jsonl) -
    callers iterating multiple certificates must catch exceptions per item.
    """
    meta = repo.get_certificate(local_id)
    if meta is None:
        raise ValueError(f"No local certificate mapping for local_id={local_id}")

    if not force and not is_renewal_due(meta):
        raise RenewalSkipped(f"Certificate {local_id} is not due for renewal yet")

    cert_dir = repo.certificate_dir(local_id)
    try:
        with renewal_lock(cert_dir, trigger):
            return _do_renew(meta, client, ca, trigger, valid_days=valid_days)
    except LockHeldError as exc:
        raise RenewalSkipped(str(exc)) from exc


def _do_renew(
    meta: CertificateMeta,
    client: NpmClient,
    ca: CertificateAuthority,
    trigger: str,
    valid_days: int | None = None,
) -> CertificateMeta:
    started_at = now_iso()
    old_expires_at = meta.cached_expires_at

    try:
        primary = meta.primary_identity()
        if primary is None:
            raise CertificateGenerationError("Certificate has no identities configured")

        issued = issue_certificate(
            ca,
            identities=meta.identities,
            primary_common_name=primary.value,
            key_type=meta.key_type,
            key_size=meta.key_size,
            valid_days=valid_days or 825,
        )

        client.upload_certificate(
            certificate_id=meta.npm_certificate_id,
            certificate_pem=issued.cert_pem.decode(),
            certificate_key_pem=issued.key_pem.decode(),
            intermediate_certificate_pem=ca.certificate_pem.decode(),
        )

        # Refresh expiry from NPM's own view after upload (source of truth).
        npm_cert = client.get_certificate(meta.npm_certificate_id)

        meta.cached_expires_at = npm_cert.expires_on
        meta.last_renewed_at = now_iso()
        meta.last_renewal_status = "ok"
        meta.last_renewal_error = None
        # No automatic reload is ever triggered (see plan.md 2.3/7) - only a
        # persistent, manually-acknowledged notice is shown in the UI.
        meta.reload_required = True
        meta.reload_required_since = now_iso()
        repo.save_certificate(meta)

        repo.append_history(
            meta.local_id,
            HistoryEntry(
                started_at=started_at,
                finished_at=now_iso(),
                status="success",
                trigger=trigger,  # type: ignore[arg-type]
                old_expires_at=old_expires_at,
                new_expires_at=meta.cached_expires_at,
            ),
        )
        return meta

    except (CertificateGenerationError, NpmError) as exc:
        logger.warning("Renewal failed for certificate %s: %s", meta.local_id, exc)
        meta.last_renewal_status = "failed"
        meta.last_renewal_error = str(exc)
        repo.save_certificate(meta)
        repo.append_history(
            meta.local_id,
            HistoryEntry(
                started_at=started_at,
                finished_at=now_iso(),
                status="failed",
                trigger=trigger,  # type: ignore[arg-type]
                old_expires_at=old_expires_at,
                new_expires_at=None,
                error_message=str(exc),
            ),
        )
        raise


def acknowledge_reload(local_id: str) -> CertificateMeta:
    """Called when the operator confirms in the UI that NPM has been
    manually restarted/reloaded - clears the reload_required banner state.
    """
    meta = repo.get_certificate(local_id)
    if meta is None:
        raise ValueError(f"No local certificate mapping for local_id={local_id}")
    meta.reload_required = False
    meta.reload_required_since = None
    return repo.save_certificate(meta)
