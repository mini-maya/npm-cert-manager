"""Background scheduler - plan.md section 7/13 Phase 6.

Runs periodically (CHECK_INTERVAL_SECONDS), using a dedicated NPM service
account (no interactive user involved - see plan.md 9.1). A failed renewal
for one certificate never stops the loop for the others.
"""
from __future__ import annotations

import logging

from apscheduler.schedulers.background import BackgroundScheduler

from app.certificates.ca import CaNotFoundError, CertificateAuthority
from app.config import settings
from app.npm.errors import NpmError
from app.services.renewal import RenewalSkipped, is_renewal_due, renew_certificate
from app.services.sync import sync_certificates
from app.storage import repository as repo
from app.web.auth import get_service_client

logger = logging.getLogger("npm_cert_manager.scheduler")


def run_check_cycle() -> None:
    """One full cycle: sync -> filter -> renew where due. Never raises -
    all exceptions are logged so a single bad cycle does not kill the
    scheduler thread.
    """
    try:
        client = get_service_client()
    except NpmError as exc:
        logger.error("Scheduler could not authenticate against NPM: %s", exc)
        return

    try:
        try:
            sync_certificates(client)
        except NpmError as exc:
            logger.error("Scheduler sync failed: %s", exc)
            return

        try:
            ca = CertificateAuthority(settings.ca_key_path, settings.ca_cert_path)
        except CaNotFoundError as exc:
            logger.error("Scheduler cannot renew: %s", exc)
            return

        for meta in repo.list_certificates():
            if not meta.auto_renew:
                continue
            if not is_renewal_due(meta):
                continue
            try:
                renew_certificate(meta.local_id, client, ca, trigger="scheduler", force=False)
                logger.info("Renewed certificate %s (%s)", meta.local_id, meta.name)
            except RenewalSkipped as exc:
                logger.info("Skipped renewal for %s: %s", meta.local_id, exc)
            except Exception as exc:  # noqa: BLE001 - must never abort the loop
                logger.error("Renewal failed for %s: %s", meta.local_id, exc)
    finally:
        client.close()


def start_scheduler() -> BackgroundScheduler:
    scheduler = BackgroundScheduler()
    scheduler.add_job(
        run_check_cycle,
        "interval",
        seconds=settings.check_interval_seconds,
        id="renewal_check_cycle",
        # Avoid overlapping runs if a cycle takes longer than the interval -
        # combined with the per-certificate lockfile this fully prevents
        # double renewals even across a restart, see plan.md 6.4.
        max_instances=1,
        coalesce=True,
    )
    scheduler.start()
    return scheduler
