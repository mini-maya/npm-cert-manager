"""Server-rendered dashboard (Jinja2 + HTMX, no SPA) - plan.md section 11.

Kept intentionally thin: all real logic lives in app.services /
app.storage / app.npm. Routes here only fetch data and render templates.
"""
from __future__ import annotations

from pathlib import Path

from fastapi import APIRouter, Cookie, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

from app.config import settings
from app.npm.errors import NpmAuthError, NpmConnectionError
from app.services.renewal import remaining_days
from app.services.sync import create_mapping as create_mapping_service, discover_unmapped
from app.storage import repository as repo
from app.web.auth import get_client_for_session, login as do_login
from app.web.auth import session_store

router = APIRouter()
templates = Jinja2Templates(directory=str(Path(__file__).resolve().parent / "templates"))


def _current_session_id(session_id: str | None) -> str | None:
    if session_id and session_store.get(session_id):
        return session_id
    return None


@router.get("/", response_class=HTMLResponse)
def dashboard(
    request: Request,
    session_id: str | None = Cookie(default=None, alias=settings.session_cookie_name),
) -> HTMLResponse:
    sid = _current_session_id(session_id)
    if not sid:
        return RedirectResponse(url="/login", status_code=302)

    certs = repo.list_certificates()
    ca_ready = settings.ca_key_path.exists() and settings.ca_cert_path.exists()
    rows = []
    any_reload_required = False
    for meta in certs:
        days = remaining_days(meta)
        if meta.reload_required:
            any_reload_required = True
        if days is None:
            color = "grey"
        elif days < 0:
            color = "red"
        elif days <= meta.renew_before_days:
            color = "orange"
        else:
            color = "green"
        rows.append({
            "meta": meta,
            "remaining_days": days,
            "color": color,
            "details": meta.model_dump(),
        })

    client = get_client_for_session(sid)
    try:
        unmapped = discover_unmapped(client)
    except Exception:
        unmapped = []
    finally:
        client.close()

    return templates.TemplateResponse(
        request,
        "dashboard.html",
        {
            "rows": rows,
            "any_reload_required": any_reload_required,
            "ca_ready": ca_ready,
            "unmapped": [
                {
                    "id": cert.id,
                    "nice_name": cert.nice_name,
                    "domain_names": cert.domain_names,
                    "expires_on": cert.expires_on,
                }
                for cert in unmapped
            ],
        },
    )


@router.get("/health-status", response_class=HTMLResponse)
def health_status_fragment() -> HTMLResponse:
    from app.npm.client import NpmClient

    client = NpmClient(settings.npm_url, timeout_seconds=5.0)
    try:
        reachable = client.ping()
    finally:
        client.close()
    text = "NPM Status: Connected" if reachable else "NPM Status: Unreachable"
    return HTMLResponse(text)


@router.get("/login", response_class=HTMLResponse)
def login_form(request: Request, error: str | None = None) -> HTMLResponse:
    return templates.TemplateResponse(request, "login.html", {"error": error})


@router.post("/login", response_model=None)
def login_submit(
    request: Request,
    identity: str = Form(...),
    secret: str = Form(...),
) -> RedirectResponse | HTMLResponse:
    try:
        session_id = do_login(identity, secret)
    except NpmAuthError:
        return templates.TemplateResponse(
            request,
            "login.html",
            {"error": "Login fehlgeschlagen - bitte NPM-Zugangsdaten pruefen."},
            status_code=401,
        )
    except NpmConnectionError:
        return templates.TemplateResponse(
            request,
            "login.html",
            {"error": "Nginx Proxy Manager ist aktuell nicht erreichbar."},
            status_code=502,
        )

    response = RedirectResponse(url="/", status_code=302)
    response.set_cookie(
        key=settings.session_cookie_name,
        value=session_id,
        httponly=True,
        secure=settings.session_cookie_secure,
        samesite="lax",
        max_age=settings.session_max_age_seconds,
    )
    return response


@router.post("/map-certificate")
def map_certificate(
    request: Request,
    session_id: str | None = Cookie(default=None, alias=settings.session_cookie_name),
    npm_certificate_id: int = Form(...),
    name: str = Form(...),
    identities: str = Form(...),
) -> RedirectResponse:
    if not session_id or not session_store.get(session_id):
        return RedirectResponse(url="/login", status_code=302)

    parsed_identities = []
    for raw in [p.strip() for p in identities.split(",") if p.strip()]:
        if ":" in raw:
            kind, value = raw.split(":", 1)
            parsed_identities.append({"type": kind.strip().upper(), "value": value.strip(), "is_primary": False})
        else:
            parsed_identities.append({"type": "DNS", "value": raw.strip(), "is_primary": False})
    if parsed_identities:
        parsed_identities[0]["is_primary"] = True

    create_mapping_service(
        npm_certificate_id=npm_certificate_id,
        name=name,
        identities=parsed_identities,
        renew_before_days=30,
    )
    return RedirectResponse(url="/", status_code=303)


@router.post("/logout")
def logout_submit(
    session_id: str | None = Cookie(default=None, alias=settings.session_cookie_name),
) -> RedirectResponse:
    if session_id:
        session_store.destroy(session_id)
    response = RedirectResponse(url="/login", status_code=302)
    response.delete_cookie(settings.session_cookie_name)
    return response
