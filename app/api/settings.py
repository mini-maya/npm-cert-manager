from __future__ import annotations

from fastapi import APIRouter, Depends
from pydantic import BaseModel

from app.api.deps import require_session
from app.storage import repository as repo
from app.storage.models import AppSettings

router = APIRouter()


@router.get("/settings", response_model=AppSettings)
def get_settings(session_id: str = Depends(require_session)) -> AppSettings:
    return repo.load_app_settings()


class SettingsIn(BaseModel):
    renew_before_days: int | None = None
    check_interval_seconds: int | None = None
    key_size: int | None = None
    key_type: str | None = None


@router.put("/settings", response_model=AppSettings)
def update_settings(payload: SettingsIn, session_id: str = Depends(require_session)) -> AppSettings:
    current = repo.load_app_settings()
    updated = current.model_copy(update={k: v for k, v in payload.model_dump().items() if v is not None})
    repo.save_app_settings(updated)
    return updated
