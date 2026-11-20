# MITRE ATLAS Threat Intelligence Mapping

Verified against the official MITRE ATLAS (Adversarial Threat Landscape for Artificial-Intelligence Systems) taxonomy at [atlas.mitre.org](https://atlas.mitre.org).

---

## Mapped ATLAS Techniques

| ATLAS ID | Technique Name | Traceon Engine Check | Policy Action |
| :--- | :--- | :--- | :--- |
| **AML.T0010** | **ML Supply Chain Compromise** | In-toto attestation check &amp; CycloneDX 1.7 AI-BOM verification | Fails CI/CD pipeline on missing or invalid signature |
| **AML.T0040** | **ML Model Deserialization Attacks** | `pickle_scan`: disassembles bytecode opcodes with `pickletools` to intercept deny-listed imports (`posix.system`, `subprocess`) | **BLOCK** (Deterministic: TRUE, Confidence: HIGH) |
| **AML.T0018** | **Backdoor ML Model** | `weight_stats`: per-layer weight tensor statistical norm comparison vs baseline | **QUARANTINE** (Deterministic: FALSE, Confidence: MEDIUM) |
| **AML.T0020** | **Poison Training Data** | `dataset_guard`: validates file magic bytes, flags unexpected scripts, verifies cryptographic hashes | **BLOCK** / **QUARANTINE** depending on executable presence |
| **AML.T0043** | **Craft Adversarial Data** | Safetensors header validation: prevents offset memory manipulation | **BLOCK** on malformed offset bounds |

---

## Corresponding Common Weakness Enumeration (CWE) Mappings

- **CWE-502:** Deserialization of Untrusted Data
- **CWE-829:** Inclusion of Functionality from Untrusted Control Sphere
- **CWE-353:** Missing Support for Integrity Check
- **CWE-494:** Download of Code Without Integrity Check
