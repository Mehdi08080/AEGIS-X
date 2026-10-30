# -*- coding: utf-8 -*-
from __future__ import annotations

import sqlite3
from typing import Any, Dict, List


class DatabaseManager:
    def __init__(self, db_path: str = "aegis_x.db") -> None:
        self.db_path = db_path
        self._initialize()

    def _initialize(self) -> None:
        conn = sqlite3.connect(self.db_path)
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS findings (
                id TEXT PRIMARY KEY,
                title TEXT NOT NULL,
                severity TEXT NOT NULL,
                confidence REAL NOT NULL,
                summary TEXT NOT NULL,
                evidence TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS policies (
                resource TEXT NOT NULL,
                action TEXT NOT NULL,
                effect TEXT NOT NULL,
                scope TEXT NOT NULL,
                rationale TEXT NOT NULL
            )
            """
        )
        conn.commit()
        conn.close()

    def save_finding(self, finding: Any) -> None:
        conn = sqlite3.connect(self.db_path)
        conn.execute(
            "INSERT OR REPLACE INTO findings (id, title, severity, confidence, summary, evidence) VALUES (?, ?, ?, ?, ?, ?)",
            (
                finding.id,
                finding.title,
                finding.severity,
                finding.confidence,
                finding.summary,
                repr(finding.evidence),
            ),
        )
        conn.commit()
        conn.close()

    def list_findings(self) -> List[Dict[str, Any]]:
        conn = sqlite3.connect(self.db_path)
        rows = conn.execute(
            "SELECT id, title, severity, confidence, summary, evidence FROM findings ORDER BY created_at DESC"
        ).fetchall()
        conn.close()
        return [
            {
                "id": row[0],
                "title": row[1],
                "severity": row[2],
                "confidence": row[3],
                "summary": row[4],
                "evidence": row[5],
            }
            for row in rows
        ]
