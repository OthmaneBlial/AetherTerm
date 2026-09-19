"""Validation of untrusted browser and agent WebSocket frames."""

import base64
import binascii
import json
import uuid

from .agents import DEVICE_ID
from .limits import MAX_FRAME_BYTES, MAX_TERMINAL_BYTES


class ProtocolError(ValueError):
    pass


def _string(value, name: str, limit: int) -> str:
    if not isinstance(value, str) or not value or len(value) > limit:
        raise ProtocolError(f"Invalid {name}")
    return value


def _session_id(value) -> str:
    session_id = _string(value, "session ID", 36)
    try:
        uuid.UUID(session_id)
    except ValueError as exc:
        raise ProtocolError("Invalid session ID") from exc
    return session_id


def _payload(value) -> str:
    encoded = _string(value, "terminal data", 4 * MAX_TERMINAL_BYTES // 3 + 8)
    try:
        binary = base64.b64decode(encoded, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ProtocolError("Invalid terminal data") from exc
    if len(binary) > MAX_TERMINAL_BYTES:
        raise ProtocolError("Terminal data too large")
    return encoded


def parse_message(raw: str, peer: str) -> dict:
    if not isinstance(raw, str) or len(raw.encode("utf-8")) > MAX_FRAME_BYTES:
        raise ProtocolError("Message too large")
    try:
        message = json.loads(raw)
    except (ValueError, RecursionError) as exc:
        raise ProtocolError("Invalid JSON") from exc
    if not isinstance(message, dict):
        raise ProtocolError("Message must be an object")
    kind = message.get("type")
    browser_types = {"list_devices", "start_session", "term_input", "resize", "close_session"}
    agent_types = {"register", "term_data", "heartbeat", "session_ready", "session_exit"}
    allowed = browser_types if peer == "browser" else agent_types if peer == "agent" else set()
    if not isinstance(kind, str) or kind not in allowed:
        raise ProtocolError("Unsupported message type")

    if kind in ("register", "start_session"):
        device_id = _string(message.get("deviceId"), "device ID", 64)
        if not DEVICE_ID.fullmatch(device_id):
            raise ProtocolError("Invalid device ID")
    if kind == "register":
        _string(message.get("token"), "credential", 256)
        description = message.get("description", "")
        if not isinstance(description, str) or len(description) > 120:
            raise ProtocolError("Invalid description")
    if kind in ("term_input", "term_data", "resize", "close_session", "session_ready", "session_exit"):
        _session_id(message.get("sessionId"))
    if kind == "term_input":
        _payload(message.get("input"))
    if kind == "term_data":
        _payload(message.get("data"))
    if kind == "resize":
        for name, upper in (("cols", 500), ("rows", 200)):
            value = message.get(name)
            if type(value) is not int or not 2 <= value <= upper:
                raise ProtocolError(f"Invalid {name}")
    return message
