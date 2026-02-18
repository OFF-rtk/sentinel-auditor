# Sentinel Auditor

**AI-Powered Transaction Auditing for Behavioral Security**

Sentinel Auditor is the investigation and compliance layer of the Sentinel ecosystem. It intercepts flagged transactions from the Vault Treasury pipeline, runs them through a hierarchical LLM reasoning chain (routing between fast and reasoning models), and produces auditable investigation traces — replacing static fraud rules with semantic policy evaluation.

The system is split into two independently deployable services:

## Components

| Service | Description | Docs |
|---------|-------------|------|
| **API** | FastAPI backend — agentic RAG pipeline, LLM orchestration, policy retrieval, Supabase persistence | [API README](auditor/api/README.md) |
| **Dashboard** | Next.js SOC interface — real-time log feed, 3D threat globe, agent decision replay graph | [Dashboard README](auditor/dashboard/README.md) |

## Quick Start

```bash
cd auditor
docker-compose up --build
```

| Service | URL |
|---------|-----|
| API | `http://localhost:8000` |
| Dashboard | `http://localhost:3001` |

## Related Repositories

- [**Sentinel ML**](https://github.com/OFF-rtk/sentinel-ml) — Behavioral biometric engine (keystroke dynamics, mouse physics, trust scoring)
- [**Vault Treasury**](https://github.com/OFF-rtk/vault-treasury) — Treasury management platform protected by Sentinel
