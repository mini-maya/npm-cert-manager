"""HTTP client for the Nginx Proxy Manager REST API.

Behaviour is based on a direct source-code analysis of the NPM `develop`
branch (see plan.md sections 2 and 3), in particular:

* ``POST /api/tokens`` with ``{identity, secret}`` returns either
  ``{token, expires}`` or a 2FA challenge (backend/routes/tokens.js,
  backend/internal/token.js).
* ``GET /api/tokens?expiry=`` refreshes an existing, still-valid token.
* Requests are authenticated via ``Authorization: Bearer <token>``
  (backend/lib/express/jwt.js).
* ``GET /api/nginx/certificates`` / ``GET /api/nginx/certificates/{id}``
  list/return certificates, including custom ("other" provider) ones.
* ``POST /api/nginx/certificates/{id}/upload`` is the *only* way to update a
  custom certificate's key material (multipart fields: ``certificate``,
  ``certificate_key``, optional ``intermediate_certificate``). It does
  **not** trigger an nginx reload (backend/internal/certificate.js:upload).
* ``POST /api/nginx/certificates/{id}/renew`` is rejected for anything other
  than ``provider == "letsencrypt"`` (backend/internal/certificate.js:renew)
  and is therefore intentionally *not* used by this client for custom
  certificates.

No nginx reload is ever triggered by this client - see plan.md section 2.3:
the application only shows a manual-action notice to the operator instead of
attempting any reload workaround.
"""
from __future__ import annotations

import time
from dataclasses import dataclass

import httpx

from app.npm.errors import (
    NpmAuthError,
    NpmConnectionError,
    NpmError,
    NpmNotFoundError,
    NpmValidationError,
)
from app.npm.models import NpmCertificate


@dataclass
class _CachedToken:
    token: str
    expires_at_epoch: float


class NpmClient:
    """One instance per "identity" (either an interactive user session or the
    scheduler's service account). Not shared/reused across different NPM
    users, so token caches never leak between accounts.
    """

    def __init__(self, base_url: str, timeout_seconds: float = 30.0) -> None:
        self._base_url = base_url.rstrip("/")
        self._client = httpx.Client(base_url=self._base_url, timeout=timeout_seconds)
        self._cached: _CachedToken | None = None

    def close(self) -> None:
        self._client.close()

    def ping(self) -> bool:
        """Lightweight reachability probe - does not require authentication
        and does not attempt to log in. Used only for health-check display.
        """
        try:
            response = self._client.get("/")
        except httpx.RequestError:
            return False
        return response.status_code < 500

    # --- Authentication ----------------------------------------------

    def login(self, identity: str, secret: str) -> str:
        """Logs in with identity/secret against POST /api/tokens.

        Returns the raw NPM token on success. Raises NpmAuthError if NPM
        rejects the credentials (including the 2FA-challenge case, which
        this minimal client does not attempt to resolve automatically).
        """
        try:
            response = self._client.post("/tokens", json={"identity": identity, "secret": secret})
        except httpx.RequestError as exc:
            raise NpmConnectionError(f"Could not reach NPM at {self._base_url}: {exc}") from exc

        if response.status_code != 200:
            raise NpmAuthError(f"NPM login failed with status {response.status_code}: {response.text}")

        data = response.json()
        if "token" not in data:
            # A 2FA challenge_token was returned instead of a token.
            raise NpmAuthError("NPM requires 2FA verification, which is not supported by this login flow")

        token = data["token"]
        expires_at_epoch = time.time() + 20 * 60 * 60  # conservative fallback (NPM default is 1 day)
        self._cached = _CachedToken(token=token, expires_at_epoch=expires_at_epoch)
        return token

    def set_token(self, token: str) -> None:
        """Allows callers (e.g. the web session store) to inject an already
        obtained token instead of logging in again.
        """
        self._cached = _CachedToken(token=token, expires_at_epoch=time.time() + 20 * 60 * 60)

    def _auth_headers(self) -> dict:
        if not self._cached:
            raise NpmAuthError("Not logged in to NPM")
        return {"Authorization": f"Bearer {self._cached.token}"}

    def _request(self, method: str, path: str, retry_on_401: bool = True, **kwargs) -> httpx.Response:
        try:
            response = self._client.request(method, path, headers=self._auth_headers(), **kwargs)
        except httpx.RequestError as exc:
            raise NpmConnectionError(f"Network error calling NPM {method} {path}: {exc}") from exc

        if response.status_code == 401 and retry_on_401:
            # Token expired/invalid - the caller is responsible for re-login
            # (interactive sessions must prompt the user again; the
            # scheduler's service account re-authenticates automatically,
            # see app.services.renewal).
            raise NpmAuthError("NPM token expired or invalid (401) - re-login required")

        return response

    # --- Certificates ---------------------------------------------------

    def list_certificates(self) -> list[NpmCertificate]:
        response = self._request("GET", "/nginx/certificates")
        self._raise_for_status(response)
        return [NpmCertificate.model_validate(row) for row in response.json()]

    def get_certificate(self, certificate_id: int) -> NpmCertificate:
        response = self._request("GET", f"/nginx/certificates/{certificate_id}")
        if response.status_code == 404:
            raise NpmNotFoundError(f"NPM certificate {certificate_id} not found")
        self._raise_for_status(response)
        return NpmCertificate.model_validate(response.json())

    def upload_certificate(
        self,
        certificate_id: int,
        certificate_pem: str,
        certificate_key_pem: str,
        intermediate_certificate_pem: str | None = None,
    ) -> dict:
        """Uploads new key material for an existing *custom* ("other"
        provider) certificate via POST /nginx/certificates/{id}/upload.

        This is the only supported renewal mechanism for custom
        certificates - POST .../renew is rejected by NPM for anything but
        letsencrypt certificates (see module docstring).
        """
        files = {
            "certificate": ("certificate.pem", certificate_pem.encode(), "application/x-pem-file"),
            "certificate_key": ("certificate_key.pem", certificate_key_pem.encode(), "application/x-pem-file"),
        }
        if intermediate_certificate_pem:
            files["intermediate_certificate"] = (
                "intermediate_certificate.pem",
                intermediate_certificate_pem.encode(),
                "application/x-pem-file",
            )

        response = self._request("POST", f"/nginx/certificates/{certificate_id}/upload", files=files)
        if response.status_code == 404:
            raise NpmNotFoundError(f"NPM certificate {certificate_id} not found")
        if response.status_code >= 400:
            raise NpmValidationError(f"NPM rejected certificate upload: {response.status_code} {response.text}")
        return response.json()

    @staticmethod
    def _raise_for_status(response: httpx.Response) -> None:
        if response.status_code >= 500:
            raise NpmConnectionError(f"NPM server error {response.status_code}: {response.text}")
        if response.status_code >= 400:
            raise NpmError(f"NPM request failed: {response.status_code} {response.text}")
