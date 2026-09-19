"""Agent connection settings checked before opening a socket."""

from dataclasses import dataclass
import ipaddress
from pathlib import Path
import re


DEVICE_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}\Z")


def server_uri(host: str, port: int, tls: bool) -> str:
    if not host or any(character in host for character in "/@?# ") or not 1 <= port <= 65535:
        raise ValueError("Invalid server host or port")
    try:
        loopback = ipaddress.ip_address(host).is_loopback
    except ValueError:
        loopback = host.lower() == "localhost"
    if not tls and not loopback:
        raise ValueError("Remote agents require --tls and a verified WSS server")
    formatted_host = f"[{host}]" if ":" in host and not host.startswith("[") else host
    return f"{'wss' if tls else 'ws'}://{formatted_host}:{port}/client"


@dataclass(frozen=True)
class AgentConfig:
    host: str
    port: int
    device_id: str
    token_file: Path
    description: str = ""
    tls: bool = False
    ca_file: Path | None = None

    def validate(self) -> None:
        server_uri(self.host, self.port, self.tls)
        if not DEVICE_ID.fullmatch(self.device_id):
            raise ValueError("Device ID must be 1–64 ASCII letters, digits, dots, underscores or hyphens")
        if len(self.description) > 120 or any(ord(char) < 32 for char in self.description):
            raise ValueError("Description must be at most 120 characters on one line")
        if self.ca_file and not self.tls:
            raise ValueError("--ca-file requires --tls")
        if self.ca_file and not self.ca_file.is_file():
            raise ValueError("CA file not found")
