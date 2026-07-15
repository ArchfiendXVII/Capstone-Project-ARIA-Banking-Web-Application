from __future__ import annotations

from typing import Protocol

from compliance.state import ScanState


class Agent(Protocol):
    name: str

    def run(self, state: ScanState, ctx: dict) -> ScanState: ...
