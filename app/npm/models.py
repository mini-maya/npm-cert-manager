"""Pydantic models mirroring the relevant subset of the NPM REST API, as
verified against backend/schema/components/*.json and backend/internal
/certificate.js of the analysed nginx-proxy-manager repository (develop
branch). Only the fields actually used by this application are modelled.
"""
from __future__ import annotations

from pydantic import BaseModel


class NpmTokenResponse(BaseModel):
    token: str
    expires: str


class NpmTokenChallengeResponse(BaseModel):
    """Returned by POST /api/tokens instead of a token when 2FA is enabled."""

    challenge_token: str | None = None


class NpmCertificate(BaseModel):
    id: int
    provider: str
    nice_name: str
    domain_names: list[str] = []
    expires_on: str | None = None
    created_on: str | None = None
    modified_on: str | None = None

    class Config:
        extra = "ignore"
