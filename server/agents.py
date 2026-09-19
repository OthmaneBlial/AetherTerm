"""Durable, device-bound credentials for Linux agents."""

from __future__ import annotations

from contextlib import contextmanager
import fcntl
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import secrets
import tempfile
import time

from .auth import operator_file


DEVICE_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}\Z")


def agents_file() -> Path:
    configured = os.environ.get("AETHERTERM_AGENTS_FILE")
    return Path(configured).expanduser() if configured else operator_file().parent / "agents.json"


def _digest(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _load(path: Path) -> dict:
    if not path.exists():
        return {"version": 1, "devices": {}}
    data = json.loads(path.read_text(encoding="utf-8"))
    if data.get("version") != 1 or not isinstance(data.get("devices"), dict):
        raise ValueError("Invalid agent registry")
    return data


def _store(path: Path, data: dict) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile("w", encoding="utf-8", dir=path.parent, prefix=".agents-", delete=False) as output:
        temporary = Path(output.name)
        os.fchmod(output.fileno(), 0o600)
        json.dump(data, output, sort_keys=True)
        output.write("\n")
        output.flush()
        os.fsync(output.fileno())
    try:
        os.replace(temporary, path)
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise


@contextmanager
def _locked(path: Path):
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    lock_path = path.with_name(path.name + ".lock")
    fd = os.open(lock_path, os.O_RDWR | os.O_CREAT, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    finally:
        fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)


def issue_credential(path: Path, device_id: str, token_file: Path, *, rotate: bool = False) -> None:
    if not DEVICE_ID.fullmatch(device_id):
        raise ValueError("Device ID must be 1–64 ASCII letters, digits, dots, underscores or hyphens")
    token_file.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    with _locked(path):
        data = _load(path)
        existing = data["devices"].get(device_id)
        if rotate:
            if existing is None or existing.get("revoked"):
                raise ValueError("Only an active enrolled device can be rotated")
        elif existing is not None:
            raise ValueError("Device already exists; use rotate with a new token file")
        token = secrets.token_urlsafe(32)
        fd = os.open(token_file, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as output:
                output.write(token + "\n")
            data["devices"][device_id] = {
                "token_hash": _digest(token), "revoked": False,
                "created_at": existing.get("created_at") if existing else int(time.time()),
                "rotated_at": int(time.time()),
            }
            _store(path, data)
        except BaseException:
            token_file.unlink(missing_ok=True)
            raise


def revoke_device(path: Path, device_id: str) -> None:
    with _locked(path):
        data = _load(path)
        existing = data["devices"].get(device_id)
        if existing is None or existing.get("revoked"):
            raise ValueError("Device is not active")
        existing["revoked"] = True
        existing["revoked_at"] = int(time.time())
        _store(path, data)


class AgentRegistry:
    def __init__(self, path: Path):
        self.path = path

    def authenticate(self, device_id: str, token: str) -> str | None:
        if not DEVICE_ID.fullmatch(device_id) or not token:
            return None
        token_hash = _digest(token)
        return token_hash if self.is_active(device_id, token_hash) else None

    def is_active(self, device_id: str, token_hash: str) -> bool:
        try:
            record = _load(self.path)["devices"].get(device_id)
            return bool(
                record and not record.get("revoked")
                and hmac.compare_digest(record["token_hash"], token_hash)
            )
        except (OSError, ValueError, TypeError, KeyError):
            return False
