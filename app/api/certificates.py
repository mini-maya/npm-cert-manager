from __future__ import annotations

import io
import re
import zipfile

from fastapi import APIRouter, Depends, Form, HTTPException, Response, status
from fastapi.responses import StreamingResponse
from pydantic import BaseModel

from app.api.deps import get_npm_client, require_session
from app.certificates.ca import CaNotFoundError, CertificateAuthority, ensure_root_ca
from app.certificates.generator import CertificateGenerationError, issue_certificate
from app.certificates.validation import classify_and_validate
from app.config import settings
from app.npm.errors import NpmError
from app.services.renewal import RenewalSkipped, acknowledge_reload, remaining_days, renew_certificate
from app.storage import repository as repo
from app.storage.models import Identity

router = APIRouter()


class CertificateOut(BaseModel):
    local_id: str
    npm_certificate_id: int
    name: str
    identities: list[dict]
    cached_expires_at: str | None
    remaining_days: int | None
    renew_before_days: int
    last_renewed_at: str | None
    last_renewal_status: str | None
    last_renewal_error: str | None
    reload_required: bool
    reload_required_since: str | None


def _to_out(meta) -> CertificateOut:
    return CertificateOut(
        local_id=meta.local_id,
        npm_certificate_id=meta.npm_certificate_id,
        name=meta.name,
        identities=[i.model_dump() for i in meta.identities],
        cached_expires_at=meta.cached_expires_at,
        remaining_days=remaining_days(meta),
        renew_before_days=meta.renew_before_days,
        last_renewed_at=meta.last_renewed_at,
        last_renewal_status=meta.last_renewal_status,
        last_renewal_error=meta.last_renewal_error,
        reload_required=meta.reload_required,
        reload_required_since=meta.reload_required_since,
    )


@router.get("/certificates", response_model=list[CertificateOut])
def list_certificates(session_id: str = Depends(require_session)) -> list[CertificateOut]:
    return [_to_out(m) for m in repo.list_certificates()]


@router.get("/certificates/{local_id}", response_model=CertificateOut)
def get_certificate(local_id: str, session_id: str = Depends(require_session)) -> CertificateOut:
    meta = repo.get_certificate(local_id)
    if meta is None:
        raise HTTPException(status_code=404, detail="Certificate mapping not found")
    return _to_out(meta)


@router.get("/certificates/{local_id}/history")
def get_history(local_id: str, session_id: str = Depends(require_session)) -> list[dict]:
    if repo.get_certificate(local_id) is None:
        raise HTTPException(status_code=404, detail="Certificate mapping not found")
    return [entry.model_dump() for entry in repo.read_history(local_id)]


@router.post("/certificates/{local_id}/renew", response_model=CertificateOut)
def renew(
    local_id: str,
    valid_days: int = Form(825),
    session_id: str = Depends(require_session),
) -> CertificateOut:
    client = get_npm_client(session_id)
    try:
        ca = CertificateAuthority(settings.ca_key_path, settings.ca_cert_path)
        meta = renew_certificate(local_id, client, ca, trigger="manual", force=True, valid_days=valid_days)
        return _to_out(meta)
    except RenewalSkipped as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc
    except CaNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=str(exc)) from exc
    except (CertificateGenerationError, NpmError) as exc:
        raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail=str(exc)) from exc
    finally:
        client.close()


@router.post("/certificates/{local_id}/acknowledge-reload", response_model=CertificateOut)
def acknowledge(local_id: str, session_id: str = Depends(require_session)) -> CertificateOut:
    try:
        return _to_out(acknowledge_reload(local_id))
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.delete("/certificates/{local_id}", response_model=None, status_code=status.HTTP_204_NO_CONTENT)
def delete_mapping(local_id: str, session_id: str = Depends(require_session)) -> None:
    if repo.get_certificate(local_id) is None:
        raise HTTPException(status_code=404, detail="Certificate mapping not found")
    repo.delete_certificate(local_id)
    return None


class CreateMappingIn(BaseModel):
    npm_certificate_id: int
    name: str
    identities: list[dict]
    renew_before_days: int = 30


@router.post("/certificates", response_model=CertificateOut, status_code=status.HTTP_201_CREATED)
def create_mapping(payload: CreateMappingIn, session_id: str = Depends(require_session)) -> CertificateOut:
    from app.services.sync import create_mapping as create_mapping_service

    meta = create_mapping_service(
        npm_certificate_id=payload.npm_certificate_id,
        name=payload.name,
        identities=payload.identities,
        renew_before_days=payload.renew_before_days,
    )
    return _to_out(meta)


@router.post("/certificates/discover")
def discover(session_id: str = Depends(require_session)) -> list[dict]:
    from app.services.sync import discover_unmapped

    client = get_npm_client(session_id)
    try:
        return [c.model_dump() for c in discover_unmapped(client)]
    finally:
        client.close()


@router.post("/ca/init")
def initialize_ca(
    common_name: str = Form("Local Docker Root CA"),
    valid_days: int = Form(825),
) -> dict:
    key_path = settings.ca_key_path
    cert_path = settings.ca_cert_path

    if key_path.exists() and cert_path.exists():
        return {"status": "exists", "created": False}

    created = ensure_root_ca(
        ca_key_path=key_path,
        ca_cert_path=cert_path,
        common_name=common_name,
        valid_days=valid_days,
        key_size=settings.key_size,
    )
    return {"status": "created" if created else "exists", "created": created}


def _parse_sans(raw_sans: str) -> list[Identity]:
    values = [part.strip() for part in re.split(r"[,\n;]+", raw_sans) if part.strip()]
    if not values:
        raise ValueError("Mindestens ein DNS- oder IP-SAN muss angegeben werden")

    identities: list[Identity] = []
    for value in values:
        identity_type, normalized = classify_and_validate(value)
        identities.append(Identity(type=identity_type, value=normalized, is_primary=(value == values[0])))
    return identities


@router.post("/certificates/generate")
def generate_certificate(
    common_name: str = Form(...),
    sans: str = Form(...),
    days: int = Form(825),
    session_id: str = Depends(require_session),
) -> Response:
    if common_name is None or sans is None:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="common_name und sans sind Pflichtfelder")

    if not settings.ca_key_path.exists() or not settings.ca_cert_path.exists():
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="Root CA fehlt. Bitte erst Root CA erzeugen.")

    try:
        identities = _parse_sans(sans)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc

    try:
        ca = CertificateAuthority(settings.ca_key_path, settings.ca_cert_path)
        issued = issue_certificate(
            ca,
            identities=identities,
            primary_common_name=common_name or identities[0].value,
            key_type=settings.key_type,
            key_size=settings.key_size,
            valid_days=days,
        )
    except (CertificateGenerationError, CaNotFoundError, ValueError) as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc

    slug = re.sub(r"[^a-z0-9]+", "-", common_name.lower()).strip("-") or "certificate"
    zip_buffer = io.BytesIO()
    with zipfile.ZipFile(zip_buffer, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(f"{slug}.crt", issued.cert_pem)
        zf.writestr(f"{slug}.key", issued.key_pem)
        zf.writestr("ca.crt", ca.certificate_pem)

    zip_buffer.seek(0)
    return StreamingResponse(
        zip_buffer,
        media_type="application/zip",
        headers={"Content-Disposition": f'attachment; filename="{slug}.zip"'},
    )
