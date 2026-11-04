#Tool tab identities only

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class WorkspaceTabs:
    opened: list[str] = field(default_factory=lambda: ["dashboard"])
    active: str = "dashboard"

    def select(self, key: str) -> None:
        if key not in self.opened:
            self.opened.append(key)
        self.active = key

    def close(self, key: str) -> None:
        if key not in self.opened:
            return
        position = self.opened.index(key)
        self.opened.remove(key)
        if not self.opened:
            self.opened.append("dashboard")
        if self.active == key:
            self.active = self.opened[max(0, position - 1)]

    def cycle(self, backwards: bool = False) -> str:
        offset = -1 if backwards else 1
        self.active = self.opened[(self.opened.index(self.active) + offset) % len(self.opened)]
        return self.active
