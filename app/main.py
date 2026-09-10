"""FastAPI application entrypoint - wires together the API routers, the
Jinja2/HTMX web UI and the background scheduler.
"""
from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles

from app.api import certificates as api_certificates
from app.api import health as api_health
from app.api import login as api_login
from app.api import settings as api_settings
from app.api import sync as api_sync
from app.scheduler import start_scheduler
from app.web import routes as web_routes


class _SecretRedactionFilter(logging.Filter):
    """Strips PEM key/certificate blocks from any log record, as a defense-
    in-depth measure against accidental logging of key material - see
    plan.md section 9 ("Logging-Verbot").
    """

    def filter(self, record: logging.LogRecord) -> bool:
        msg = record.getMessage()
        if "-----BEGIN" in msg:
            record.msg = "[redacted: message contained PEM key/certificate material]"
            record.args = ()
        return True


def _configure_logging() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    logging.getLogger().addFilter(_SecretRedactionFilter())


@asynccontextmanager
async def lifespan(app: FastAPI):
    _configure_logging()
    scheduler = start_scheduler()
    try:
        yield
    finally:
        scheduler.shutdown(wait=False)


app = FastAPI(title="NPM Certificate Manager", lifespan=lifespan)

app.mount(
    "/static",
    StaticFiles(directory=str(Path(__file__).resolve().parent / "web" / "static")),
    name="static",
)

app.include_router(api_health.router, prefix="/api", tags=["health"])
app.include_router(api_login.router, prefix="/api", tags=["auth"])
app.include_router(api_certificates.router, prefix="/api", tags=["certificates"])
app.include_router(api_sync.router, prefix="/api", tags=["sync"])
app.include_router(api_settings.router, prefix="/api", tags=["settings"])
app.include_router(web_routes.router, tags=["web"])
