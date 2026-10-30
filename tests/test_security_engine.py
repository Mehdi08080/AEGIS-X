# -*- coding: utf-8 -*-
from __future__ import annotations

from aegis_x.security_intelligence import SecurityIntelligenceEngine


def test_core_graph_and_attack_path() -> None:
    engine = SecurityIntelligenceEngine()
    result = engine.run_assessment(
        assets=[
            {"id": "public-web", "name": "public-web", "type": "application", "criticality": 0.8, "exposure": "internet"},
            {"id": "config-db", "name": "config-db", "type": "database", "criticality": 0.95, "exposure": "internal"},
        ],
        relationships=[
            {"source": "public-web", "target": "config-db", "kind": "depends_on", "strength": 0.9},
        ],
        policies=[
            {"resource": "config-db", "action": "read", "effect": "deny", "scope": "global", "rationale": "data minimization"},
        ],
        events=[
            {"timestamp": "2026-10-30T12:00:00Z", "actor": "ops-user", "action": "grant_role", "service": "identity"},
            {"timestamp": "2026-10-30T12:05:00Z", "actor": "ops-user", "action": "upload_sensitive", "service": "storage"},
        ],
        ai_flows=[
            {"user": "customer", "agent": "assistant", "tool": "browser", "data_source": "customer-db", "destination": "public-web", "request_summary": "retrieve user profile"},
        ],
    )
    assert result["summary"]["finding_count"] >= 2
    assert result["ai_findings"][0]["status"] == "warning"


def test_policy_engine_allows_or_denies() -> None:
    from aegis_x.policy_engine import PolicyEngine
    from aegis_x.models import Policy

    engine = PolicyEngine()
    policy = Policy(resource="db", action="read", effect="deny", scope="global", rationale="restrict")
    decision = engine.evaluate([policy], "db", "read")
    assert decision["allowed"] is False


def test_api_health() -> None:
    from fastapi.testclient import TestClient
    from aegis_x.api import app

    client = TestClient(app)
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"
