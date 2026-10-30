# -*- coding: utf-8 -*-
from __future__ import annotations

from dataclasses import dataclass
from typing import List, Optional

from .models import Evidence, Finding


@dataclass
class EvidenceEngine:
    def build_finding(
        self,
        title: str,
        severity: str,
        confidence: float,
        summary: str,
        impact: str,
        affected_assets: List[str],
        evidence: List[Evidence],
        detection_method: str,
        policy_ref: Optional[str] = None,
    ) -> Finding:
        return Finding(
            id=f"finding-{abs(hash(title + summary))}",
            title=title,
            severity=severity,
            confidence=confidence,
            summary=summary,
            impact=impact,
            affected_assets=affected_assets,
            evidence=evidence,
            detection_method=detection_method,
            policy_ref=policy_ref,
            verification_status="evidence-backed",
            recommended_action="Review and restrict trust transitions.",
        )
