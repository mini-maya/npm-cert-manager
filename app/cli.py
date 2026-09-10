from __future__ import annotations

import argparse
import os
from pathlib import Path

from app.certificates.ca import generate_root_ca
from app.config import settings


def init_ca(common_name: str | None = None, key_size: int | None = None, validity_days: int | None = None) -> None:
    key_path = settings.ca_key_path
    cert_path = settings.ca_cert_path

    key_path.parent.mkdir(parents=True, exist_ok=True)
    cert_path.parent.mkdir(parents=True, exist_ok=True)

    if key_path.exists() or cert_path.exists():
        raise FileExistsError(f"CA files already exist at {key_path} and {cert_path}; refusing to overwrite them")

    issued = generate_root_ca(
        common_name=common_name or os.environ.get("CA_COMMON_NAME", "Local Docker Root CA"),
        valid_days=validity_days or 365 * 20,
        key_size=key_size or settings.key_size,
    )

    key_path.write_bytes(issued.key_pem)
    cert_path.write_bytes(issued.cert_pem)
    os.chmod(key_path, 0o600)
    os.chmod(cert_path, 0o644)
    print(f"Created CA key: {key_path}")
    print(f"Created CA cert: {cert_path}")


def main() -> None:
    parser = argparse.ArgumentParser(description="NPM Certificate Manager CLI")
    sub = parser.add_subparsers(dest="command", required=True)

    init = sub.add_parser("init-ca", help="Create the local Root CA key+certificate if missing")
    init.add_argument("--common-name", default=None)
    init.add_argument("--key-size", type=int, default=None)
    init.add_argument("--validity-days", type=int, default=None)

    args = parser.parse_args()
    if args.command == "init-ca":
        init_ca(args.common_name, args.key_size, args.validity_days)


if __name__ == "__main__":
    main()
