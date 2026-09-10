"""FastAPI dependencies shared across API routers: session-cookie extraction
and NPM-client construction. Kept separate from app.web.auth (pure logic)
so the storage/auth layer stays framework-agnostic.
"""
from __future__ import annotations

from fastapi import Cookie, HTTPException, status

from app.config import settings
from app.npm.client import NpmClient
from app.npm.errors import NpmAuthError
from app.web.auth import get_client_for_session, session_store


def require_session(
    session_id: str | None = Cookie(default=None, alias=settings.session_cookie_name),
) -> str:
    if not session_id:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated")
    session = session_store.get(session_id)
    if session is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Session expired, please log in again")
    return session_id


def get_npm_client(session_id: str) -> NpmClient:
    try:
        return get_client_for_session(session_id)
    except NpmAuthError as exc:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=str(exc)) from exc
