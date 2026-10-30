# AEGIS-X

AEGIS-X is an independent cybersecurity and AI security intelligence platform designed to model digital trust relationships, reason about exposure propagation, analyze AI-specific security risks, and generate evidence-backed findings.

## Current status

This repository contains a real MVP foundation for a native security intelligence engine.

## Core components

- Security knowledge graph
- Contextual attack path reasoning
- AI security flow analysis
- Behavioral anomaly analysis
- Evidence and confidence engine
- Risk prioritization
- FastAPI assessment API
- SQLite-based findings persistence
- CI/CD and Docker deployment primitives

## Quick start

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
pytest -q
uvicorn aegis_x.api:app --reload
```

## Repository

https://github.com/Mehdi08080/AEGIS-X
