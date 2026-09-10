"""Certificate discovery / sync service - plan.md section 7, steps 1-3.

Reads the current certificate list from NPM, filters for custom
("other" provider) certificates, and reconciles them against the local
mapping stored under /app/data/certificates/*/meta.json. Certificates that
exist in NPM but have no local mapping yet are reported separately so they
can be onboarded explicitly (no automatic onboarding without confirmation -
see plan.md section 14).
"""
from __future__ import annotations

from dataclasses import dataclass

from app.npm.client import NpmClient
from app.npm.models import NpmCertificate
from app.storage import repository as repo
from app.storage.models import CertificateMeta, now_iso

CUSTOM_PROVIDER = "other"


@dataclass
class SyncResult:
    synced: list[CertificateMeta]
    unmapped: list[NpmCertificate]


def sync_certificates(client: NpmClient) -> SyncResult:
    npm_certs = [c for c in client.list_certificates() if c.provider == CUSTOM_PROVIDER]
    npm_by_id = {c.id: c for c in npm_certs}

    synced: list[CertificateMeta] = []
    for meta in repo.list_certificates():
        npm_cert = npm_by_id.get(meta.npm_certificate_id)
        if npm_cert is None:
            # Mapped locally, but no longer present (or no longer custom) in
            # NPM - leave the local record untouched except for a sync
            # timestamp; surfaced to the operator via the dashboard/history.
            continue
        meta.cached_expires_at = npm_cert.expires_on
        meta.last_synced_at = now_iso()
        repo.save_certificate(meta)
        synced.append(meta)

    mapped_npm_ids = {m.npm_certificate_id for m in repo.list_certificates()}
    unmapped = [c for c in npm_certs if c.id not in mapped_npm_ids]

    return SyncResult(synced=synced, unmapped=unmapped)


def discover_unmapped(client: NpmClient) -> list[NpmCertificate]:
    mapped_npm_ids = {m.npm_certificate_id for m in repo.list_certificates()}
    return [
        c
        for c in client.list_certificates()
        if c.provider == CUSTOM_PROVIDER and c.id not in mapped_npm_ids
    ]


def create_mapping(npm_certificate_id: int, name: str, identities: list[dict], renew_before_days: int = 30) -> CertificateMeta:
    from app.storage.models import Identity

    meta = CertificateMeta(
        npm_certificate_id=npm_certificate_id,
        name=name,
        identities=[Identity(**i) for i in identities],
        renew_before_days=renew_before_days,
    )
    return repo.create_certificate(meta)
