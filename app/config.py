"""Central application configuration, sourced entirely from environment
variables (see .env.example). No secrets are ever hard-coded here.
"""
from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


def _read_secret(value_env: str, file_env: str, default: str | None = None) -> str | None:
    """Reads a secret either directly from an env var or from a file path
    referenced by another env var (Docker-secrets-friendly convention:
    ``FOO`` or ``FOO_FILE``).

    Missing secret files do not crash the application at import time; they are
    treated as "not configured" and can be handled by the caller later.
    """
    file_path = os.environ.get(file_env)
    if file_path:
        p = Path(file_path)
        if p.exists():
            return p.read_text(encoding="utf-8").strip()
        return None
    value = os.environ.get(value_env)
    return value if value not in (None, "") else default


@dataclass(frozen=True)
class Settings:
    npm_url: str
    npm_service_identity: str | None
    npm_service_secret: str | None

    renew_before_days: int
    check_interval_seconds: int
    key_size: int
    key_type: str

    ca_key_path: Path
    ca_cert_path: Path

    data_dir: Path

    session_secret: str
    session_cookie_name: str
    session_cookie_secure: bool
    session_max_age_seconds: int

    @property
    def certificates_dir(self) -> Path:
        return self.data_dir / "certificates"

    @property
    def settings_file(self) -> Path:
        return self.data_dir / "settings.json"


def load_settings() -> Settings:
    return Settings(
        npm_url=os.environ.get("NPM_URL", "http://nginx-proxy-manager:81/api").rstrip("/"),
        npm_service_identity=os.environ.get("NPM_SERVICE_IDENTITY"),
        npm_service_secret=_read_secret("NPM_SERVICE_SECRET", "NPM_SERVICE_SECRET_FILE"),
        renew_before_days=int(os.environ.get("RENEW_BEFORE_DAYS", "30")),
        check_interval_seconds=int(os.environ.get("CHECK_INTERVAL_SECONDS", "21600")),
        key_size=int(os.environ.get("KEY_SIZE", "2048")),
        key_type=os.environ.get("KEY_TYPE", "rsa"),
        ca_key_path=Path(os.environ.get("CA_KEY_PATH", "/app/secrets/ca.key")),
        ca_cert_path=Path(os.environ.get("CA_CERT_PATH", "/app/secrets/ca.crt")),
        data_dir=Path(os.environ.get("DATA_DIR", "/app/data")),
        session_secret=os.environ.get("SESSION_SECRET", "change-me"),
        session_cookie_name=os.environ.get("SESSION_COOKIE_NAME", "cert_manager_session"),
        session_cookie_secure=os.environ.get("SESSION_COOKIE_SECURE", "false").lower() in {"1", "true", "yes", "on"},
        session_max_age_seconds=int(os.environ.get("SESSION_MAX_AGE_SECONDS", "86400")),
    )


settings = load_settings()
