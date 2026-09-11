"""Root CA loading and signing - the only component in the whole application
allowed to touch ``ca.key``.

Hard security invariant (see plan.md section 9): the CA private key object
never leaves this module in any exportable form. Callers only ever get back
``(server_key_pem, server_cert_pem)`` tuples for freshly issued server
certificates - never the CA key itself.
"""
from __future__ import annotations

import datetime
from dataclasses import dataclass
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import NameOID


class CaNotFoundError(Exception):
    """Raised when ca.key/ca.crt do not exist yet - the CA must be created
    explicitly out-of-band (see plan.md section 10), never implicitly.
    """


@dataclass(frozen=True)
class IssuedCertificate:
    key_pem: bytes
    cert_pem: bytes


def read_certificate_details(cert_path: Path) -> dict[str, str] | None:
    """Read subject, issuer and expiry metadata from a PEM certificate."""
    if not cert_path.is_file():
        return None

    certificate = x509.load_pem_x509_certificate(cert_path.read_bytes())
    try:
        expiry = certificate.not_valid_after_utc
    except AttributeError:
        expiry = certificate.not_valid_after
    if getattr(expiry, "tzinfo", None) is None:
        expiry = expiry.replace(tzinfo=datetime.timezone.utc)

    return {
        "issuer": certificate.issuer.rfc4514_string(),
        "expiry": expiry.astimezone(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
        "subject": certificate.subject.rfc4514_string(),
    }


class CertificateAuthority:
    """Loads ca.key/ca.crt once and signs server certificates. Never expose
    ``_private_key`` outside this class.
    """

    def __init__(self, ca_key_path: Path, ca_cert_path: Path) -> None:
        if not ca_key_path.is_file() or not ca_cert_path.is_file():
            raise CaNotFoundError(
                f"CA key/cert not found at {ca_key_path} / {ca_cert_path}. "
                "Create the root CA out-of-band before starting the scheduler/web UI."
            )
        self._private_key = serialization.load_pem_private_key(ca_key_path.read_bytes(), password=None)
        self._certificate = x509.load_pem_x509_certificate(ca_cert_path.read_bytes())

    @property
    def certificate_pem(self) -> bytes:
        """The CA *certificate* (public, safe to expose/download)."""
        return self._certificate.public_bytes(serialization.Encoding.PEM)

    def sign_server_certificate(
        self,
        common_name: str,
        san_entries: list[x509.GeneralName],
        key_type: str = "rsa",
        key_size: int = 2048,
        valid_days: int = 825,
    ) -> IssuedCertificate:
        """Generates a fresh private key + CSR + signed server certificate.

        A new private key is generated on every call by design (see
        plan.md "bevorzugt neuer Private Key bei jedem Renewal") - there is
        no key-reuse code path.
        """
        private_key = _generate_private_key(key_type, key_size)

        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
        now = datetime.datetime.now(datetime.timezone.utc)

        builder = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(self._certificate.subject)
            .public_key(private_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(minutes=5))
            .not_valid_after(now + datetime.timedelta(days=valid_days))
            .add_extension(x509.SubjectAlternativeName(san_entries), critical=False)
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    key_encipherment=True,
                    content_commitment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=False,
                    crl_sign=False,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=False,
            )
            .add_extension(x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=False)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(private_key.public_key()), critical=False)
            .add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_public_key(self._certificate.public_key()),
                critical=False,
            )
        )

        certificate = builder.sign(private_key=self._private_key, algorithm=hashes.SHA256())

        key_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        cert_pem = certificate.public_bytes(serialization.Encoding.PEM)
        return IssuedCertificate(key_pem=key_pem, cert_pem=cert_pem)


def _generate_private_key(key_type: str, key_size: int):
    if key_type == "ecdsa":
        return ec.generate_private_key(ec.SECP256R1())
    return rsa.generate_private_key(public_exponent=65537, key_size=key_size)


def generate_root_ca(common_name: str, valid_days: int = 825, key_size: int = 4096) -> IssuedCertificate:
    """Creates a brand-new, self-signed Root CA key+certificate.

    Default values match the legacy bash script for compatibility with the
    existing local-root-CA workflow.
    """
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    now = datetime.datetime.now(datetime.timezone.utc)

    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=valid_days))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(private_key.public_key()),
            critical=False,
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(private_key.public_key()),
            critical=False,
        )
        .sign(private_key=private_key, algorithm=hashes.SHA256())
    )

    key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    cert_pem = certificate.public_bytes(serialization.Encoding.PEM)
    return IssuedCertificate(key_pem=key_pem, cert_pem=cert_pem)


def ensure_root_ca(ca_key_path: Path, ca_cert_path: Path, common_name: str = "Local Docker Root CA", valid_days: int = 825, key_size: int = 4096) -> bool:
    """Create a CA pair when both files are missing, mirroring the legacy bash script behavior.

    Returns True when a new CA was generated, False when it already existed.
    """
    if ca_key_path.exists() and ca_cert_path.exists():
        return False
    if ca_key_path.exists() != ca_cert_path.exists():
        raise ValueError(
            f"Incomplete CA pair: {ca_key_path} and {ca_cert_path} must either both exist or both be missing."
        )

    ca_key_path.parent.mkdir(parents=True, exist_ok=True)
    ca_cert_path.parent.mkdir(parents=True, exist_ok=True)

    issued = generate_root_ca(common_name=common_name, valid_days=valid_days, key_size=key_size)
    ca_key_path.write_bytes(issued.key_pem)
    ca_cert_path.write_bytes(issued.cert_pem)
    ca_key_path.chmod(0o600)
    ca_cert_path.chmod(0o644)
    return True
