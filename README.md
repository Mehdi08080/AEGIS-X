# AEGIS-X

AEGIS-X is an independent cybersecurity and AI security intelligence platform that models digital trust, calculates potential exposure paths, evaluates AI-specific risk, and produces evidence-backed findings.

## Overview

The project is designed around a native security intelligence engine instead of a wrapper around external tools. It integrates:

- Security knowledge graph analysis
- Contextual attack path reasoning
- AI security and trust-flow evaluation
- Behavioral anomaly analysis
- Policy-aware evidence generation
- Risk prioritization and reproducible assessment outputs

## Quick start

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
pytest -q
uvicorn aegis_x.api:app --reload
```

## API

- Health: `GET /health`
- Assessment: `POST /run-assessment`
- Findings: `GET /findings`

## Implementation status

This repository contains a real working MVP implementation of the core engine and assessment stack. It is intentionally designed to be modular, evidence-based, and reasonably secure.
