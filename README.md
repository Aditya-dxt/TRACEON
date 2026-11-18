# Traceon: Complete AI Supply Chain Security & Trust Platform

> **"Trace Every Layer. Trust Every Model."**  
> Team: **DeepTrace AI** · Repository: [https://github.com/Aditya-dxt/TRACEON](https://github.com/Aditya-dxt/TRACEON) · Branch: `main`

---

## 1. Executive Overview

Traceon protects the entire lifecycle of enterprise AI: from model and dataset ingestion, through development and CI/CD pipelines, to runtime deployment and agent tool usage. 

### Core Tenet
**"LLMs Explain. Deterministic Checks Decide."**  
Critical security decisions, policy gates, and cryptographic signatures are never delegated to probabilistic LLM outputs. Deterministic static checks and versioned policy rules decide verdicts; AI models (such as Gemini) are restricted to explanation and summary assistance.

---

## 2. Team & Folder Ownership

To enable rapid independent development without merge friction, each team member owns a strictly dedicated folder:

| Person | Role | Owns Folder | Scope / Deliverables |
| :--- | :--- | :--- | :--- |
| **Aditya Dixit** | CEO, AI & Security Engineering Lead | `scanner/` | Pickle opcode scanner, Safetensors verifier, dataset guard, weight statistics, CycloneDX AI-BOM generator, Gemini model-card parser, synthetic test corpus. |
| **Vaibhav Tripathi** | CTO, Backend & Platform | `backend/`, `infra/` | FastAPI REST services, PostgreSQL/SQLite schemas, Cloud Run sandbox worker, Hugging Face connector, deterministic policy engine, hash-chained audit log, KMS DSSE signing, verify CLI, GitHub Action. |
| **Aadya Pandey** | Product & Design Lead | `frontend/`, `docs/` | Next.js/Tailwind security dashboard, hero finding card, AI-BOM interactive graph, attestation & verify UI, demo script, research & pitch deck. |
| **Shared** | All Three | `contracts/` | Canonical JSON schemas (`finding`, `scan_result`, `verdict`, `attestation`), `api.md`, and mock example JSON. |

---

## 3. Repository Layout

```text
TRACEON/
├── README.md                     # Setup overview and team rules
├── .gitignore                    # Secrets, env files, and large models ignored
├── contracts/                    # Shared contract schemas and mock data
│   ├── finding.schema.json       # JSON Schema for an individual finding
│   ├── scan_result.schema.json   # JSON Schema for scanner output
│   ├── verdict.schema.json       # JSON Schema for policy decision
│   ├── attestation.schema.json   # JSON Schema for in-toto DSSE attestation
│   ├── api.md                    # REST API endpoint specifications
│   └── examples/                 # Realistic mock JSON files for all states
├── scanner/                      # Aditya: AI & model security analysis
│   ├── corpus/                   # Harmless synthetic test fixtures
│   ├── pickle_scan/              # Safe opcode disassembler
│   ├── safetensors_verify/       # Header & boundary validator
│   ├── dataset_guard/            # Dataset inspection & integrity
│   ├── weights/                  # Tensor statistics and anomaly heuristics
│   ├── bom/                      # CycloneDX 1.7 AI-BOM generator
│   ├── explain/                  # Gemini model-card parser (explanation only)
│   ├── tests/                    # Unit tests across checks
│   └── cli.py                    # Scanner CLI interface
├── backend/                      # Vaibhav: Platform API, policy, and signing
│   ├── app/                      # FastAPI endpoints & models
│   ├── policy/                   # Deterministic 4-verdict rule engine
│   ├── signing/                  # Cloud KMS in-toto DSSE signer
│   ├── connectors/               # Hugging Face quarantine intake
│   ├── audit/                    # Hash-chained append-only audit trail
│   └── tests/                    # Integration & API tests
├── infra/                        # Vaibhav: Cloud infrastructure & CI/CD
│   ├── sandbox/                  # Ephemeral no-egress scan container
│   ├── github_action/            # Attestation verification CI gate
│   └── deploy/                   # Cloud Run and storage deployment config
├── frontend/                     # Aadya: Next.js security console
│   ├── src/                      # UI components, views, config
│   └── mock/                     # Mock fixtures
└── docs/                         # Aadya: Research, demo, and pitch assets
    ├── demo_script.md            # 5-minute technical demo walkthrough
    ├── pitch/                    # Startup pitch deck notes
    └── research/                 # MITRE ATLAS mappings and competitor analysis
```

---

## 4. Git Collaboration Rules

1. **Strict Folder Boundaries**: Only modify files within your assigned folder. Never modify another member's folder. Changes to `contracts/` must be agreed upon by the entire team first.
2. **Commit Small and Often**: One working unit per commit.
3. **Commit Prefix**: Prefix all commit messages with your folder name:
   - `scanner: ...`
   - `backend: ...`
   - `infra: ...`
   - `frontend: ...`
   - `contracts: ...`
   - `docs: ...`
4. **Never Commit Secrets or Real Large Models**:
   - Secrets (`.env`, private keys) must stay in `.gitignore`.
   - Never commit model files over a few MBs. All test corpus models must be tiny and synthetic.
5. **Standard Push Routine**:
   ```bash
   git pull --rebase origin main
   git add <your-folder>/
   git commit -m "<folder>: description"
   git push origin main
   ```

---

## 5. Scanner Interface (Aditya's Lane)

The scanner exposes both a clean Python API and a CLI:

### Python API
```python
from scanner import scan_artifact, scan_dataset, generate_bom

# Scan model file (returns Scan Result conforming to contracts/scan_result.schema.json)
result = scan_artifact("path/to/model.safetensors")

# Scan dataset directory
ds_result = scan_dataset("path/to/dataset_dir")

# Generate CycloneDX 1.7 AI-BOM
bom = generate_bom(model_meta, scan_results)
```

### CLI
```bash
python -m scanner.cli scan --file <path>
python -m scanner.cli dataset --dir <path>
python -m scanner.cli bom --meta meta.json --scans scans.json
```
