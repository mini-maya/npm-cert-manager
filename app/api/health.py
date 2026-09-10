from __future__ import annotations

from fastapi import APIRouter

from app.config import settings
from app.npm.client import NpmClient

router = APIRouter()


@router.get("/health")
def health() -> dict:
    client = NpmClient(settings.npm_url, timeout_seconds=5.0)
    try:
        npm_status = "reachable" if client.ping() else "unreachable"
    finally:
        client.close()

    return {"status": "ok", "npm_status": npm_status}
