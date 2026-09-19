"""Validated paths for one AetherTerm server process."""

from dataclasses import dataclass
from pathlib import Path

from .agents import agents_file
from .auth import operator_file


@dataclass(frozen=True)
class ServerConfig:
    operator_path: Path
    agents_path: Path
    assets_path: Path

    @classmethod
    def from_paths(cls, *, operator_path: Path | None, agents_path: Path | None,
                   assets_path: Path) -> "ServerConfig":
        config = cls(operator_path or operator_file(), agents_path or agents_file(), assets_path)
        if config.operator_path.resolve() == config.agents_path.resolve():
            raise ValueError("Operator and agent registry must use different private files")
        if not config.assets_path.is_dir():
            raise RuntimeError(f"AetherTerm Web assets not found: {config.assets_path}")
        for name in ("index.html", "login.html", "favicon.svg", "favicon.ico", "assets/app.js", "assets/app.css"):
            if not (config.assets_path / name).is_file():
                raise RuntimeError(f"AetherTerm Web asset not found: {config.assets_path / name}")
        return config
