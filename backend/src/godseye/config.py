# SPDX-License-Identifier: Apache-2.0
"""Validated native configuration. Callers choose paths before starting the application."""

from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True, slots=True)
class Settings:
    root: Path
    state: Path
    web: Path
    port: int = 8765
    bind: str = "127.0.0.1"

    @property
    def host(self) -> str:
        return f"127.0.0.1:{self.port}"

    def validated(self) -> "Settings":
        if not 1 <= self.port <= 65535:
            raise ValueError("Invalid server arguments")
        if self.bind not in {"127.0.0.1", "0.0.0.0"}:
            raise ValueError("bind must be 127.0.0.1 or 0.0.0.0")
        root = self.root.resolve(strict=True)
        if not root.is_dir():
            raise ValueError("workspace must be a directory")
        web = self.web.resolve(strict=True)
        if not (web / "index.html").is_file():
            raise ValueError("Build the frontend first: npm run build in apps/web")
        state = self.state.resolve()
        if state == root:
            raise ValueError("state must have its own directory")
        return Settings(root=root, state=state, web=web, port=self.port, bind=self.bind)
