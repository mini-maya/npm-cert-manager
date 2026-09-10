"""Turns a list of validated identities into `cryptography` SAN objects and
performs the pre-upload sanity check described in plan.md step 9 of the
renewal algorithm (key/cert match, SAN correctness, not-yet-expired).
"""
from __future__ import annotations

import ipaddress

from cryptography import x509
from cryptography.hazmat.primitives import serialization

from app.certificates.ca import CertificateAuthority, IssuedCertificate
from app.certificates.validation import InvalidIdentityError, classify_and_validate
from app.storage.models import Identity


class CertificateGenerationError(Exception):
    pass


def build_san_entries(identities: list[Identity]) -> list[x509.GeneralName]:
    entries: list[x509.GeneralName] = []
    for identity in identities:
        try:
            id_type, value = classify_and_validate(identity.value)
        except InvalidIdentityError as exc:
            raise CertificateGenerationError(str(exc)) from exc

        if id_type == "IP":
            entries.append(x509.IPAddress(ipaddress.ip_address(value)))
        else:
            entries.append(x509.DNSName(value))
    if not entries:
        raise CertificateGenerationError("At least one SAN identity is required")
    return entries


def issue_certificate(
    ca: CertificateAuthority,
    identities: list[Identity],
    primary_common_name: str,
    key_type: str = "rsa",
    key_size: int = 2048,
    valid_days: int = 397,
) -> IssuedCertificate:
    san_entries = build_san_entries(identities)
    issued = ca.sign_server_certificate(
        common_name=primary_common_name,
        san_entries=san_entries,
        key_type=key_type,
        key_size=key_size,
        valid_days=valid_days,
    )
    _verify_key_matches_cert(issued)
    return issued


def _verify_key_matches_cert(issued: IssuedCertificate) -> None:
    """Defense-in-depth: verify the freshly generated key and certificate
    actually belong together before anything is ever uploaded to NPM (plan.md
    renewal algorithm step 9).
    """
    private_key = serialization.load_pem_private_key(issued.key_pem, password=None)
    certificate = x509.load_pem_x509_certificate(issued.cert_pem)

    key_public_numbers = private_key.public_key().public_numbers()
    cert_public_numbers = certificate.public_key().public_numbers()
    if key_public_numbers != cert_public_numbers:
        raise CertificateGenerationError("Generated private key does not match the signed certificate")

    import datetime

    now = datetime.datetime.now(datetime.timezone.utc)
    if certificate.not_valid_after_utc <= now:
        raise CertificateGenerationError("Generated certificate is already expired")
