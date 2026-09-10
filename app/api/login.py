from __future__ import annotations

from fastapi import APIRouter, Cookie, HTTPException, Response, status
from pydantic import BaseModel

from app.config import settings
from app.npm.errors import NpmAuthError, NpmConnectionError
from app.web.auth import login as do_login
from app.web.auth import session_store

router = APIRouter()


class LoginIn(BaseModel):
    identity: str
    secret: str


@router.post("/login")
def login(payload: LoginIn, response: Response) -> dict:
    """Forwards identity/secret 1:1 to NPM's own POST /api/tokens. No
    credentials are stored locally beyond this single request - see
    plan.md section 9.1.
    """
    try:
        session_id = do_login(payload.identity, payload.secret)
    except NpmAuthError as exc:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=str(exc)) from exc
    except NpmConnectionError as exc:
        raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail=str(exc)) from exc

    response.set_cookie(
        key=settings.session_cookie_name,
        value=session_id,
        httponly=True,
        secure=settings.session_cookie_secure,
        samesite="lax",
        max_age=settings.session_max_age_seconds,
    )
    return {"status": "ok"}


@router.post("/login/2fa")
def login_2fa() -> dict:
    """Placeholder for NPM's 2FA challenge flow (POST /api/tokens/2fa).

    Not implemented in this initial version - see plan.md section 14 open
    questions. Accounts with 2FA enabled cannot currently log in through
    this application and must use a non-2FA (or service) account instead.
    """
    raise HTTPException(
        status_code=status.HTTP_501_NOT_IMPLEMENTED,
        detail="2FA login is not yet supported by the Certificate Manager",
    )


@router.post("/logout")
def logout(
    response: Response,
    session_id: str | None = Cookie(default=None, alias=settings.session_cookie_name),
) -> dict:
    if session_id:
        session_store.destroy(session_id)
    response.delete_cookie(settings.session_cookie_name)
    return {"status": "ok"}
