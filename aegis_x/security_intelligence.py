# -*- coding: utf-8 -*-
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List

from .ai_security_engine import AISecurityEngine
from .attack_path_engine import AttackPathEngine
from .behavioral_engine import BehavioralEngine
from .evidence_engine import EvidenceEngine
from .models import AIFlow, Asset, EventRecord, Finding, Policy, Relationship
from .policy_engine import PolicyEngine
from .risk_engine import RiskEngine
from .security_graph import SecurityGraph


@dataclass
class SecurityIntelligenceEngine:
    graph: SecurityGraph = field(default_factory=SecurityGraph)
    attack_engine: AttackPathEngine = field(default_factory=AttackPathEngine)
    ai_engine: AISecurityEngine = field(default_factory=AISecurityEngine)
    behavior_engine: BehavioralEngine = field(default_factory=BehavioralEngine)
    policy_engine: PolicyEngine = field(default_factory=PolicyEngine)
    evidence_engine: EvidenceEngine = field(default_factory=EvidenceEngine)
    risk_engine: RiskEngine = field(default_factory=RiskEngine)

    def __post_init__(self) -> None:
        self.attack_engine.graph = self.graph

    def run_assessment(
        self,
        assets: List[Dict[str, Any]],
        relationships: List[Dict[str, Any]],
        policies: List[Dict[str, Any]],
        events: List[Dict[str, Any]],
        ai_flows: List[Dict[str, Any]],
    ) -> Dict[str, Any]:
        for asset_data in assets:
            asset = Asset(**asset_data)
            self.graph.add_asset(asset)

        for rel_data in relationships:
            relationship = Relationship(**rel_data)
            self.graph.add_relationship(relationship)

        policy_objects = [Policy(**policy) for policy in policies]
        event_objects = [EventRecord(**event) for event in events]
        ai_objects = [AIFlow(**flow) for flow in ai_flows]

        findings: List[Finding] = []

        for flow in ai_objects:
            ai_result = self.ai_engine.evaluate_flow(flow)
            if ai_result["status"] == "warning":
                findings.append(
                    self.evidence_engine.build_finding(
                        title="AI Data Flow Risk",
                        severity="high" if ai_result["risk_score"] > 0.5 else "medium",
                        confidence=ai_result["risk_score"],
                        summary=ai_result["summary"],
                        impact="Potential sensitive data exposure to unintended destinations.",
                        affected_assets=[flow.data_source, flow.destination],
                        evidence=[
                            type(
                                "EvidenceItem",
                                (),
                                {
                                    "source": "ai-flow",
                                    "description": ai_result["summary"],
                                    "confidence": ai_result["risk_score"],
                                    "timestamp": "2026-01-01T00:00:00Z",
                                },
                            )()
                        ],
                        detection_method="AI trust-flow policy analysis",
                        policy_ref="ai/data-flow",
                    )
                )

        for policy in policy_objects:
            decision = self.policy_engine.evaluate(policy_objects, policy.resource, policy.action)
            if not decision["allowed"]:
                findings.append(
                    self.evidence_engine.build_finding(
                        title="Policy Denial or Risk",
                        severity="medium",
                        confidence=0.75,
                        summary=decision["reason"],
                        impact="Restricted resource is still reachable through trust relationships.",
                        affected_assets=[policy.resource],
                        evidence=[
                            type(
                                "EvidenceItem",
                                (),
                                {"source": "policy", "description": decision["reason"], "confidence": 0.75, "timestamp": "2026-01-01T00:00:00Z"},
                            )()
                        ],
                        detection_method="Policy validation",
                        policy_ref="security/policy",
                    )
                )

        for asset in assets:
            if asset.get("exposure") == "internet":
                findings.append(
                    self.evidence_engine.build_finding(
                        title="Exposed Asset",
                        severity="high" if asset.get("criticality", 0) > 0.7 else "medium",
                        confidence=0.7,
                        summary=f"Asset {asset['name']} is publicly exposed and may be used as a trust anchor.",
                        impact="Attackers may leverage exposed assets to reach sensitive components.",
                        affected_assets=[asset["id"]],
                        evidence=[
                            type(
                                "EvidenceItem",
                                (),
                                {"source": "asset", "description": f"Asset {asset['name']} exposed to internet", "confidence": 0.7, "timestamp": "2026-01-01T00:00:00Z"},
                            )()
                        ],
                        detection_method="Asset exposure analysis",
                        policy_ref="asset/exposure",
                    )
                )

        behavior = self.behavior_engine.analyze_events(event_objects)
        if behavior["status"] == "warning":
            findings.append(
                self.evidence_engine.build_finding(
                    title="Behavioral Anomaly",
                    severity="high" if behavior["score"] > 0.5 else "medium",
                    confidence=behavior["score"],
                    summary="Event stream shows anomalous or elevated access patterns.",
                    impact="Potential misuse or compromise behavior may be in progress.",
                    affected_assets=[event.actor for event in event_objects],
                    evidence=[
                        type(
                            "EvidenceItem",
                            (),
                            {"source": "behavior", "description": signal, "confidence": behavior["score"], "timestamp": "2026-01-01T00:00:00Z"},
                        )()
                        for signal in behavior["signals"]
                    ],
                    detection_method="Behavioral baseline analysis",
                    policy_ref="behavior/anomaly",
                )
            )

        for rel in relationships:
            if rel.get("kind") == "depends_on":
                attack = self.attack_engine.assess_risk(rel["source"], rel["target"], max_depth=3)
                if attack["risk_score"] > 0.35:
                    findings.append(
                        self.evidence_engine.build_finding(
                            title="Privilege Chain or Dependency Exposure",
                            severity="high" if attack["risk_score"] > 0.6 else "medium",
                            confidence=attack["risk_score"],
                            summary=attack["summary"],
                            impact="Critical dependency chain creates a reachable path to sensitive resources.",
                            affected_assets=[rel["source"], rel["target"]],
                            evidence=[
                                type(
                                    "EvidenceItem",
                                    (),
                                    {"source": "attack-path", "description": f"Path {path}", "confidence": attack["risk_score"], "timestamp": "2026-01-01T00:00:00Z"},
                                )()
                                for path in attack["paths"]
                            ],
                            detection_method="Contextual attack path reasoning",
                            policy_ref="attack-path/dependency",
                        )
                    )

        prioritized = self.risk_engine.prioritize(findings)
        return {
            "summary": {
                "asset_count": len(assets),
                "relationship_count": len(relationships),
                "finding_count": len(prioritized),
            },
            "findings": [
                {
                    "id": finding.id,
                    "title": finding.title,
                    "severity": finding.severity,
                    "confidence": finding.confidence,
                    "summary": finding.summary,
                    "impact": finding.impact,
                    "affected_assets": finding.affected_assets,
                    "evidence": [
                        {
                            "source": e.source,
                            "description": e.description,
                            "confidence": e.confidence,
                            "timestamp": e.timestamp,
                        }
                        for e in finding.evidence
                    ],
                    "detection_method": finding.detection_method,
                    "policy_ref": finding.policy_ref,
                    "verification_status": finding.verification_status,
                }
                for finding in prioritized
            ],
            "attack_paths": self.attack_engine.identify_paths(assets[0]["id"], assets[-1]["id"], max_depth=3) if len(assets) > 1 else [],
            "ai_findings": [
                {
                    "status": result["status"],
                    "risk_score": result["risk_score"],
                    "issues": result["issues"],
                }
                for result in [self.ai_engine.evaluate_flow(AIFlow(**flow)) for flow in ai_flows]
            ],
            "confidence": round(sum(f.confidence for f in prioritized) / len(prioritized), 3) if prioritized else 0.0,
        }
