# -*- coding: utf-8 -*-
from __future__ import annotations

from typing import Any, Dict, List

from fastapi import FastAPI
from pydantic import BaseModel

from .security_intelligence import SecurityIntelligenceEngine
from .storage import DatabaseManager

app = FastAPI(title="AEGIS-X API", version="0.1.0")
engine = SecurityIntelligenceEngine()
store = DatabaseManager("aegis_x.db")


class AssetInput(BaseModel):
    id: str
    name: str
    type: str
    criticality: float = 0.5
    exposure: str = "internal"
    owner: str = "unknown"
    tags: List[str] = []


class RelationshipInput(BaseModel):
    source: str
    target: str
    kind: str
    strength: float = 0.5
    metadata: Dict[str, Any] = {}


class PolicyInput(BaseModel):
    resource: str
    action: str
    effect: str
    scope: str = "global"
    rationale: str = "default policy"


class EventInput(BaseModel):
    timestamp: str
    actor: str
    action: str
    service: str
    details: Dict[str, Any] = {}


class AIFlowInput(BaseModel):
    user: str
    agent: str
    tool: str
    data_source: str
    destination: str
    request_summary: str = "request"


class AssessmentRequest(BaseModel):
    assets: List[AssetInput]
    relationships: List[RelationshipInput]
    policies: List[PolicyInput]
    events: List[EventInput]
    ai_flows: List[AIFlowInput]


@app.get("/health")
def health() -> Dict[str, Any]:
    return {"status": "ok", "service": "aegis-x", "version": "0.1.0"}


@app.post("/run-assessment")
def run_assessment(request: AssessmentRequest) -> Dict[str, Any]:
    result = engine.run_assessment(
        assets=[asset.model_dump() for asset in request.assets],
        relationships=[rel.model_dump() for rel in request.relationships],
        policies=[policy.model_dump() for policy in request.policies],
        events=[event.model_dump() for event in request.events],
        ai_flows=[flow.model_dump() for flow in request.ai_flows],
    )
    return result


@app.get("/findings")
def list_findings() -> List[Dict[str, Any]]:
    return store.list_findings()
