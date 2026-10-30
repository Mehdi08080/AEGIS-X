# -*- coding: utf-8 -*-
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, List


@dataclass
class RiskEngine:
    def prioritize(self, findings: List[Any]) -> List[Any]:
        return sorted(findings, key=lambda x: self._severity_value(x.severity) * x.confidence, reverse=True)

    @staticmethod
    def _severity_value(severity: str) -> float:
        scale = {"critical": 5.0, "high": 4.0, "medium": 3.0, "low": 2.0, "info": 1.0}
        return scale.get(severity.lower(), 1.0)
