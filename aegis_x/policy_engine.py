# -*- coding: utf-8 -*-
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List


@dataclass
class PolicyEngine:
    def evaluate(self, policies: List[Any], resource: str, action: str) -> Dict[str, Any]:
        for policy in policies:
            if policy.resource == resource and policy.action == action:
                if policy.effect == "deny":
                    return {
                        "allowed": False,
                        "reason": f"Policy denies {action} on {resource}.",
                        "policy": policy,
                    }
                return {
                    "allowed": True,
                    "reason": f"Policy allows {action} on {resource}.",
                    "policy": policy,
                }
        return {
            "allowed": True,
            "reason": "No explicit policy found; default allow for analysis-only operation.",
            "policy": None,
        }
