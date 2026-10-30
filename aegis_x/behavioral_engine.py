# -*- coding: utf-8 -*-
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List


@dataclass
class BehavioralEngine:
    def analyze_events(self, events: List[Any]) -> Dict[str, Any]:
        if not events:
            return {"status": "ok", "score": 0.0, "signals": []}

        signals: List[str] = []
        score = 0.0
        actors: Dict[str, int] = {}

        for event in events:
            actors[event.actor] = actors.get(event.actor, 0) + 1

        for actor, count in actors.items():
            if count > 5:
                signals.append(f"User or service {actor} generated unusually frequent activity.")
                score += 0.25

        suspicious_actions = [event.action for event in events if event.action in {"grant_role", "upload_sensitive", "exfiltrate"}]
        if suspicious_actions:
            signals.append("Suspicious action sequence detected.")
            score += 0.35

        return {
            "status": "warning" if score > 0.25 else "ok",
            "score": round(min(0.99, score), 3),
            "signals": signals,
        }
