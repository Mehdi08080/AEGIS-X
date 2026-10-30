# -*- coding: utf-8 -*-
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List


@dataclass
class AttackPathEngine:
    graph: Any = None

    def identify_paths(self, start: str, goal: str, max_depth: int = 5) -> List[List[str]]:
        if self.graph is None:
            return []
        return self.graph.find_paths(start, goal, max_depth=max_depth)

    def assess_risk(self, start: str, goal: str, max_depth: int = 5) -> Dict[str, Any]:
        paths = self.identify_paths(start, goal, max_depth=max_depth)
        if not paths:
            return {"paths": [], "risk_score": 0.0, "summary": "No attack path detected."}

        highest = max(len(path) for path in paths)
        risk = min(0.99, 0.25 + (0.18 * highest) + (0.1 * len(paths)))
        return {
            "paths": paths,
            "risk_score": round(risk, 3),
            "summary": f"{len(paths)} path(s) identified from {start} to {goal}.",
        }
