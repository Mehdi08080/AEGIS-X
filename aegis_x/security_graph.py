# -*- coding: utf-8 -*-
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, List


@dataclass
class SecurityGraph:
    assets: dict[str, Any] = field(default_factory=dict)
    relationships: list[Any] = field(default_factory=list)

    def add_asset(self, asset: Any) -> None:
        self.assets[asset.id] = asset

    def add_relationship(self, relationship: Any) -> None:
        self.relationships.append(relationship)

    def neighbors(self, asset_id: str) -> List[str]:
        return [rel.target for rel in self.relationships if rel.source == asset_id]

    def find_paths(self, start: str, goal: str, max_depth: int = 5) -> List[List[str]]:
        results: List[List[str]] = []

        def walk(node: str, path: List[str]) -> None:
            if len(path) > max_depth:
                return
            if node == goal:
                results.append(path.copy())
                return
            for nxt in self.neighbors(node):
                if nxt not in path:
                    path.append(nxt)
                    walk(nxt, path)
                    path.pop()

        walk(start, [start])
        return results
