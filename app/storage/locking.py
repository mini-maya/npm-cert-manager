"""Lockfile-based mutual exclusion for renewals - see plan.md section 6.4.

No DBMS means no transactions, so double-renewal protection is implemented
with a plain exclusive-create lockfile per certificate directory. This is
sufficient for the single-instance deployment model this application assumes.
"""
from __future__ import annotations

import os
import time
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path

LOCK_FILENAME = ".lock"
STALE_LOCK_SECONDS = 15 * 60  # a lock older than this is considered abandoned


class LockHeldError(Exception):
    """Raised when a fresh lock already exists for a certificate."""


@dataclass
class LockInfo:
    trigger: str
    acquired_at: float


def _lock_path(cert_dir: Path) -> Path:
    return cert_dir / LOCK_FILENAME


def try_acquire(cert_dir: Path, trigger: str) -> None:
    """Atomically create the lockfile. Raises LockHeldError if a non-stale
    lock already exists; removes and replaces stale locks automatically.
    """
    lock_path = _lock_path(cert_dir)

    if lock_path.exists():
        age = time.time() - lock_path.stat().st_mtime
        if age < STALE_LOCK_SECONDS:
            raise LockHeldError(f"Lock for {cert_dir.name} is held (age={age:.0f}s)")
        # Stale lock from a crashed previous run - remove it.
        lock_path.unlink(missing_ok=True)

    fd = os.open(lock_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    try:
        os.write(fd, f"trigger={trigger}\nacquired_at={time.time()}\n".encode())
    finally:
        os.close(fd)


def release(cert_dir: Path) -> None:
    _lock_path(cert_dir).unlink(missing_ok=True)


@contextmanager
def renewal_lock(cert_dir: Path, trigger: str):
    try_acquire(cert_dir, trigger)
    try:
        yield
    finally:
        release(cert_dir)
