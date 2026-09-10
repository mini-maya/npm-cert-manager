"""Delegated authentication - plan.md section 9.1.

The Certificate Manager has no user database of its own. Login credentials
are forwarded 1:1 to NPM's own POST /api/tokens; only a successful NPM
response creates a session here. Sessions are held in-memory only (no
DBMS, consistent with the rest of the storage architecture) and are keyed
by a cryptographically random session id.
"""
from __future__ import annotations

import secrets
import threading
import time
from dataclasses import dataclass

from app.npm.client import NpmClient
from app.npm.errors import NpmAuthError, NpmConnectionError
from app.config import settings

# NPM's default token lifetime is 1 day (backend/internal/token.js) - the
# local session is intentionally never allowed to outlive that, see 9.1.
_DEFAULT_SESSION_LIFETIME_SECONDS = 20 * 60 * 60


@dataclass
class Session:
    identity: str
    npm_token: str
    created_at: float
    expires_at: float


class SessionStore:
    """Simple in-memory session store. Single-instance deployment only -
    see plan.md section 14 (no horizontal scale-out is supported)."""

    def __init__(self) -> None:
        self._sessions: dict[str, Session] = {}
        self._lock = threading.Lock()

    def create(self, identity: str, npm_token: str) -> str:
        session_id = secrets.token_urlsafe(32)
        now = time.time()
        with self._lock:
            self._sessions[session_id] = Session(
                identity=identity,
                npm_token=npm_token,
                created_at=now,
                expires_at=now + _DEFAULT_SESSION_LIFETIME_SECONDS,
            )
        return session_id

    def get(self, session_id: str) -> Session | None:
        with self._lock:
            session = self._sessions.get(session_id)
            if session is None:
                return None
            if session.expires_at < time.time():
                del self._sessions[session_id]
                return None
            return session

    def destroy(self, session_id: str) -> None:
        with self._lock:
            self._sessions.pop(session_id, None)


session_store = SessionStore()


def login(identity: str, secret: str) -> str:
    """Attempts a login against NPM. Returns a new Certificate Manager
    session id on success. Raises NpmAuthError/NpmConnectionError on
    failure - the caller (web route) must map these to a user-facing error,
    never store the raw secret anywhere beyond this function call.
    """
    client = NpmClient(settings.npm_url)
    try:
        token = client.login(identity, secret)
    finally:
        client.close()
    return session_store.create(identity=identity, npm_token=token)


def get_client_for_session(session_id: str) -> NpmClient:
    """Builds a fresh NpmClient pre-authenticated with the session's cached
    NPM token. Raises NpmAuthError if the session does not exist/expired.
    """
    session = session_store.get(session_id)
    if session is None:
        raise NpmAuthError("Session not found or expired - please log in again")
    client = NpmClient(settings.npm_url)
    client.set_token(session.npm_token)
    return client


def get_service_client() -> NpmClient:
    """Builds an NpmClient authenticated with the dedicated NPM service
    account, used exclusively by the scheduler (plan.md 9.1) - no
    interactive user is involved.
    """
    if not settings.npm_service_identity or not settings.npm_service_secret:
        raise NpmConnectionError("NPM_SERVICE_IDENTITY/NPM_SERVICE_SECRET(_FILE) are not configured")
    client = NpmClient(settings.npm_url)
    client.login(settings.npm_service_identity, settings.npm_service_secret)
    return client
