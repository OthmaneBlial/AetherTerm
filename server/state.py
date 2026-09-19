"""State owned by one AetherTerm server process."""

from dataclasses import dataclass, field
from pathlib import Path
from typing import TypedDict

from fastapi import WebSocket

from .agents import AgentRegistry
from .auth import OperatorAuth
from .limits import ConnectionLimiter


class SessionRecord(TypedDict):
    device_id: str
    web_ws: WebSocket
    ready: bool


@dataclass
class ServerState:
    operator_auth: OperatorAuth
    agent_registry: AgentRegistry
    web_dir: Path
    browser_connections: ConnectionLimiter = field(default_factory=ConnectionLimiter)
    agent_connections: ConnectionLimiter = field(default_factory=ConnectionLimiter)
    devices: dict[str, WebSocket] = field(default_factory=dict)
    device_credentials: dict[str, str] = field(default_factory=dict)
    sessions: dict[str, SessionRecord] = field(default_factory=dict)
    device_last_seen: dict[str, float] = field(default_factory=dict)
    device_descriptions: dict[str, str] = field(default_factory=dict)
