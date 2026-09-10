from __future__ import annotations

from fastapi import APIRouter, Depends

from app.api.deps import get_npm_client, require_session
from app.services.sync import sync_certificates

router = APIRouter()


@router.post("/sync")
def sync(session_id: str = Depends(require_session)) -> dict:
    client = get_npm_client(session_id)
    try:
        result = sync_certificates(client)
        return {
            "synced_count": len(result.synced),
            "unmapped_count": len(result.unmapped),
            "unmapped": [c.model_dump() for c in result.unmapped],
        }
    finally:
        client.close()
