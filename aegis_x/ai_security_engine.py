# -*- coding: utf-8 -*-
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List


@dataclass
class AISecurityEngine:
    def evaluate_flow(self, ai_flow: Any) -> Dict[str, Any]:
        issues: List[str] = []
        score = 0.0

        if ai_flow.data_source.lower().endswith("db") or "customer" in ai_flow.data_source.lower():
            issues.append("Sensitive data source is reachable by AI workflow.")
            score += 0.4

        if ai_flow.destination.lower().startswith("public") or ai_flow.destination.lower() == "external-web":
            issues.append("Sensitive data may be exposed to a public destination.")
            score += 0.4

        if ai_flow.tool.lower() in {"browser", "shell", "web_search"}:
            issues.append("Tool permissions may enable data exfiltration or unsafe delegation.")
            score += 0.2

        if not issues:
            return {"status": "ok", "risk_score": 0.0, "issues": []}

        return {
            "status": "warning",
            "risk_score": round(min(0.99, score), 3),
            "issues": issues,
            "summary": f"AI flow from {ai_flow.user} via {ai_flow.agent} to {ai_flow.tool} is unsafe.",
        }
