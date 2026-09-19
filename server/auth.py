"""Single-operator authentication for the browser control plane."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
from pathlib import Path
import secrets
import time

from .limits import SlidingWindowLimiter


COOKIE_NAME = "aetherterm_session"
SESSION_SECONDS = 8 * 60 * 60
MAX_OPERATOR_SESSIONS = 32
SCRYPT_N = 2**14
SCRYPT_R = 8
SCRYPT_P = 1


def operator_file() -> Path:
    configured = os.environ.get("AETHERTERM_OPERATOR_FILE")
    return Path(configured).expanduser() if configured else Path.home() / ".config" / "aetherterm" / "operator.json"


def _password_hash(password: str, salt: bytes) -> str:
    return hashlib.scrypt(
        password.encode("utf-8"), salt=salt, n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P
    ).hex()


def initialize_operator(path: Path, password: str) -> None:
    if len(password) < 12:
        raise ValueError("Operator password must have at least 12 characters")
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    salt = os.urandom(16)
    record = {"version": 1, "salt": salt.hex(), "hash": _password_hash(password, salt)}
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    fd = os.open(path, flags, 0o600)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as output:
            json.dump(record, output)
            output.write("\n")
    except BaseException:
        path.unlink(missing_ok=True)
        raise


class OperatorAuth:
    def __init__(self, path: Path):
        self.path = path
        self.sessions: dict[str, float] = {}
        self.sockets: dict[str, set] = {}
        self.login_attempts = SlidingWindowLimiter(5, 300)
        self._record_signature: tuple[int, int] | None = None

    def configured(self) -> bool:
        return self.path.is_file()

    def _load_record(self) -> dict | None:
        try:
            stat = self.path.stat()
            signature = (stat.st_mtime_ns, stat.st_size)
            if self._record_signature is not None and signature != self._record_signature:
                self.sessions.clear()
            self._record_signature = signature
            record = json.loads(self.path.read_text(encoding="utf-8"))
            if record.get("version") != 1:
                return None
            return record
        except (OSError, ValueError, TypeError, AttributeError):
            self.sessions.clear()
            self._record_signature = None
            return None

    def verify_password(self, password: str) -> bool:
        record = self._load_record()
        if not record:
            return False
        try:
            salt = bytes.fromhex(record["salt"])
            candidate = _password_hash(password, salt)
            return hmac.compare_digest(candidate, record["hash"])
        except (KeyError, TypeError, ValueError):
            return False

    def allow_login(self, ip: str) -> bool:
        return self.login_attempts.allow(ip)

    def create_session(self) -> str:
        now = time.monotonic()
        self.sessions = {key: expiry for key, expiry in self.sessions.items() if expiry > now}
        if len(self.sessions) >= MAX_OPERATOR_SESSIONS:
            oldest = min(self.sessions, key=self.sessions.__getitem__)
            self.sessions.pop(oldest)
        token = secrets.token_urlsafe(32)
        self.sessions[self._key(token)] = now + SESSION_SECONDS
        return token

    @staticmethod
    def _key(token: str) -> str:
        return hashlib.sha256(token.encode("utf-8")).hexdigest()

    def session_key(self, token: str | None) -> str | None:
        if not token:
            return None
        self._load_record()
        key = self._key(token)
        expiry = self.sessions.get(key, 0)
        if expiry <= time.monotonic():
            self.sessions.pop(key, None)
            return None
        return key

    def seconds_remaining(self, key: str) -> float:
        self._load_record()
        return max(0.0, self.sessions.get(key, 0) - time.monotonic())

    def register_socket(self, key: str, websocket) -> None:
        self.sockets.setdefault(key, set()).add(websocket)

    def unregister_socket(self, key: str, websocket) -> None:
        sockets = self.sockets.get(key)
        if sockets is not None:
            sockets.discard(websocket)
            if not sockets:
                self.sockets.pop(key, None)

    async def revoke(self, token: str | None) -> None:
        if not token:
            return
        key = self._key(token)
        self.sessions.pop(key, None)
        for websocket in list(self.sockets.get(key, ())):
            try:
                await websocket.close(code=1008, reason="Signed out")
            except RuntimeError:
                pass
