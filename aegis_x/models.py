# -*- coding: utf-8 -*-
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class Asset:
    id: str
    name: str
    type: str
    criticality: float = 0.5
    exposure: str = "internal"
    owner: str = "unknown"
    tags: List[str] = field(default_factory=list)


@dataclass
class Relationship:
    source: str
    target: str
    kind: str
    strength: float = 0.5
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class Evidence:
    source: str
    description: str
    confidence: float = 0.5
    timestamp: str = "2026-01-01T00:00:00Z"


@dataclass
class Finding:
    id: str
    title: str
    severity: str
    confidence: float
    summary: str
    impact: str
    affected_assets: List[str]
    evidence: List[Evidence]
    detection_method: str
    policy_ref: Optional[str] = None
    verification_status: str = "unverified"
    recommended_action: str = "Investigate"


@dataclass
class Policy:
    resource: str
    action: str
    effect: str
    scope: str = "global"
    rationale: str = "default policy"


@dataclass
class EventRecord:
    timestamp: str
    actor: str
    action: str
    service: str
    details: Dict[str, Any] = field(default_factory=dict)


@dataclass
class AIFlow:
    user: str
    agent: str
    tool: str
    data_source: str
    destination: str
    request_summary: str = "request"
