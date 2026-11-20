# AI Supply Chain Security: Competitive Landscape

| Capability / Attribute | **Traceon** (DeepTrace AI) | **Protect AI / Guardian** | **HiddenLayer MLDR** | **Standard Model Hub Scanners** (e.g. Hugging Face built-in) |
| :--- | :--- | :--- | :--- | :--- |
| **Inspection Mechanism** | **Deterministic Opcode Disassembly** (never executes `pickle.load` or `torch.load`) | Static heuristic & dynamic analysis | Behavioral inference monitoring | Basic heuristic scanning / ClamAV wrapper |
| **AI Software BOM** | **CycloneDX 1.7 JSON standard** with full lineage (model, dataset, deps) | Custom proprietary schema | Proprietary asset inventory | Basic README model cards |
| **Cryptographic Provenance** | **in-toto Statements + Cloud KMS asymmetric DSSE signatures** | Checkpoint hashing without KMS attestation | Signature checking on proprietary agent | SHA-256 commit hashes only |
| **Tamper Protection** | **1-byte change causes immediate attestation verification failure** | Hash alert | Post-execution alert | Silent re-hash on push |
| **Decision Philosophy** | **Deterministic checks decide; LLM (Gemini) explains** | Heuristics decide | ML model decides | Binary pass/fail heuristic |
| **Isolation Architecture** | **Zero-egress Cloud Run sandbox worker** | Container sandbox | Endpoint agent | Multi-tenant worker |
| **CI/CD Enforcement** | **Native GitHub Action fails pipeline on un-attested models** | CLI scanner | API integration | None |

### Key Traceon Differentiators
1. **Zero-Trust Deserialization:** Traceon disassembles opcodes purely as text and byte tokens. Unsafe files can never trigger execution in Traceon's scanner.
2. **Standard-Based Trust Chain:** Using formal in-toto statements and CycloneDX 1.7 allows enterprises to integrate Traceon into existing SLSA and software supply chain tooling.
3. **Transparent Separation:** We never allow an LLM to cast a security verdict; Gemini generates human-readable explanations, keeping policy verdicts strictly deterministic.
