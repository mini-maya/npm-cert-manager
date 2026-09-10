"""The single, centralized gateway to all on-disk state.

Every read/write of meta.json, history.jsonl and settings.json MUST go
through this module (see plan.md section 9 "Command Injection / Path
Traversal") so that path validation and atomic writes are enforced in one
place instead of being scattered across the codebase.
"""
from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path
from uuid import uuid4

from app.config import settings
from app.storage.models import AppSettings, CertificateMeta, HistoryEntry, now_iso

META_FILENAME = "meta.json"
HISTORY_FILENAME = "history.jsonl"


class PathTraversalError(Exception):
    pass


def _ensure_base_dirs() -> None:
    settings.certificates_dir.mkdir(parents=True, exist_ok=True)


def _safe_cert_dir(local_id: str) -> Path:
    """Resolves the directory for a given local_id and verifies it is
    actually contained within the certificates root - defense in depth
    against path traversal, even though local_id is always server-generated
    (see plan.md 9).
    """
    base = settings.certificates_dir.resolve()
    candidate = (base / local_id).resolve()
    if base not in candidate.parents and candidate != base:
        raise PathTraversalError(f"Refusing to access path outside data dir: {candidate}")
    return candidate


def atomic_write_json(path: Path, data: dict) -> None:
    """Writes JSON atomically: write to a temp file in the same directory,
    then os.replace() (atomic rename on POSIX), so a crash mid-write never
    leaves a corrupted file behind.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_path = tempfile.mkstemp(dir=str(path.parent), prefix=".tmp-", suffix=".json")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, sort_keys=True)
            f.write("\n")
        os.chmod(tmp_path, 0o600)
        os.replace(tmp_path, path)
    except BaseException:
        Path(tmp_path).unlink(missing_ok=True)
        raise


# --- Certificates ------------------------------------------------------


def list_certificate_ids() -> list[str]:
    _ensure_base_dirs()
    return sorted(
        p.name for p in settings.certificates_dir.iterdir() if p.is_dir() and (p / META_FILENAME).is_file()
    )


def create_certificate(meta: CertificateMeta) -> CertificateMeta:
    cert_dir = _safe_cert_dir(meta.local_id)
    cert_dir.mkdir(parents=True, exist_ok=False)
    atomic_write_json(cert_dir / META_FILENAME, meta.model_dump())
    return meta


def get_certificate(local_id: str) -> CertificateMeta | None:
    cert_dir = _safe_cert_dir(local_id)
    meta_path = cert_dir / META_FILENAME
    if not meta_path.is_file():
        return None
    return CertificateMeta.model_validate_json(meta_path.read_text(encoding="utf-8"))


def get_certificate_by_npm_id(npm_certificate_id: int) -> CertificateMeta | None:
    for local_id in list_certificate_ids():
        meta = get_certificate(local_id)
        if meta and meta.npm_certificate_id == npm_certificate_id:
            return meta
    return None


def list_certificates() -> list[CertificateMeta]:
    result = []
    for local_id in list_certificate_ids():
        meta = get_certificate(local_id)
        if meta:
            result.append(meta)
    return result


def save_certificate(meta: CertificateMeta) -> CertificateMeta:
    meta.updated_at = now_iso()
    cert_dir = _safe_cert_dir(meta.local_id)
    atomic_write_json(cert_dir / META_FILENAME, meta.model_dump())
    return meta


def delete_certificate(local_id: str) -> None:
    cert_dir = _safe_cert_dir(local_id)
    if not cert_dir.is_dir():
        return
    for child in cert_dir.iterdir():
        child.unlink()
    cert_dir.rmdir()


def certificate_dir(local_id: str) -> Path:
    return _safe_cert_dir(local_id)


# --- History (append-only) ----------------------------------------------


def append_history(local_id: str, entry: HistoryEntry) -> None:
    cert_dir = _safe_cert_dir(local_id)
    cert_dir.mkdir(parents=True, exist_ok=True)
    history_path = cert_dir / HISTORY_FILENAME
    with open(history_path, "a", encoding="utf-8") as f:
        f.write(entry.model_dump_json())
        f.write("\n")
    os.chmod(history_path, 0o600)


def read_history(local_id: str, limit: int = 50) -> list[HistoryEntry]:
    cert_dir = _safe_cert_dir(local_id)
    history_path = cert_dir / HISTORY_FILENAME
    if not history_path.is_file():
        return []
    entries: list[HistoryEntry] = []
    with open(history_path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                entries.append(HistoryEntry.model_validate_json(line))
            except ValueError:
                # Tolerate a truncated last line (e.g. crash mid-append).
                continue
    return entries[-limit:][::-1]


# --- Settings ------------------------------------------------------------


def load_app_settings() -> AppSettings:
    if not settings.settings_file.is_file():
        return AppSettings(
            renew_before_days=settings.renew_before_days,
            check_interval_seconds=settings.check_interval_seconds,
            key_size=settings.key_size,
            key_type=settings.key_type,  # type: ignore[arg-type]
        )
    return AppSettings.model_validate_json(settings.settings_file.read_text(encoding="utf-8"))


def save_app_settings(app_settings: AppSettings) -> None:
    settings.data_dir.mkdir(parents=True, exist_ok=True)
    atomic_write_json(settings.settings_file, app_settings.model_dump())


def new_local_id() -> str:
    """Generates a fresh local_id. Never derived from user input - see
    plan.md section 9 (path traversal defense).
    """
    return str(uuid4())
