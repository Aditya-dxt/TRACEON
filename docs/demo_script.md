# Traceon: 5-Minute Live Demo Script

**Team:** DeepTrace AI  
**Goal:** Demonstrate deterministic AI supply chain defense, CycloneDX 1.7 AI-BOM generation, Cloud KMS cryptographic attestation, and zero-tolerance tamper detection entirely from the browser with no terminal required.

---

## Demo Timing & Sequence (Total: 5 Minutes)

### Minute 0:00 – 1:00 | The Problem & Overview Posture
- **Action:** Open browser at `http://localhost:3000` (Overview page).
- **Say:**
  > "Every modern enterprise is downloading open-weights and fine-tuned models from public registries like Hugging Face. But serialized weights—especially legacy pickle files—run arbitrary operating system code upon deserialization. And even with Safetensors, backdoors and weight poisons can lurk undetectable. Welcome to Traceon: the deterministic AI supply chain security platform."
- **Screen Focus:** Point out the **Security Posture KPI Bar** (Model Assets, Threats Blocked, Quarantined, Approved).
- **Key Callout:** Point out the target SLA badge: *Scan Latency Goal: < 2 min | Target False Positives: < 1% (Engineering goals).*

---

### Minute 1:00 – 2:15 | The Hero View: Pickle Opcode Intercept
- **Action:** Scroll to the **Hero Finding Card** (`f_001` on `evil_model.bin`).
- **Say:**
  > "Here is our core hero view. Aditya's opcode scanner disassembled the pickle bytecode without ever executing `pickle.load`. At byte offset `0x0042`, it deterministically caught a call to `posix.system` attempting to run a shell command."
- **Screen Focus:**
  - Highlight the exact fields: Module (`posix`), Callable (`system`), Byte Offset (`0x0042`), and Artifact SHA-256.
  - Highlight the **BLOCK** verdict badge.
  - Highlight the **Gemini Explanation box**:
    > *"Notice our strict architectural principle: The LLM explains; deterministic checks decide. Gemini interprets the context for human security analysts, but deterministic bytecode analysis dictated the BLOCK verdict."*

---

### Minute 2:15 – 3:15 | Model Lineage & CycloneDX 1.7 AI-BOM
- **Action:** Click **AI-BOM Explorer** in the top navigation (`/bom`).
- **Say:**
  > "For models that do pass our inspection, we generate a formal CycloneDX 1.7 AI Software Bill of Materials."
- **Screen Focus:**
  - Point to the visual lineage flow: **Base Model (`example-org/llm-7b`) + Dataset Corpus (`fin-qa-corpus@r7`) + Packages (`transformers`) &rarr; Fine-Tuned Target (`bank-llm-7b-ft`)**.
  - Click the **Raw CycloneDX JSON** toggle to show the full compliant CycloneDX 1.7 schema with `traceon:*` properties.
  - Click **Export BOM** to show one-click compliance packaging.

---

### Minute 3:15 – 4:15 | Cloud KMS in-toto Attestation & The 1-Byte Tamper Test
- **Action:** Click **Verify & Attest** in the navigation (`/verify`).
- **Say:**
  > "When an approved model is released, Vaibhav's backend wraps the scan result and BOM digest in an in-toto statement and signs it with Google Cloud KMS. Let's verify our approved model."
- **Click:** Click the button **Clean Model (model.safetensors)**.
- **Click:** Click **Verify Attestation**.
- **Result:** The screen turns emerald green with **Attestation Cryptographically Valid (APPROVE)**, displaying the Cloud KMS key resource and digest match.
- **Say:**
  > "Now, what happens if an attacker tampers with even a single byte of weights in transit?"
- **Click:** Click the button **Simulate 1-Byte Tamper (Digest Mismatch)**.
- **Click:** Click **Verify Attestation**.
- **Result:** Instant crimson alert with **Attestation Verification FAILED (BLOCK)** showing `submitted_digest` != `attested_digest`.
- **Say:**
  > "Because the cryptographic signature binds directly to the SHA-256 digest of the scanned weights, any modification breaks verification immediately. The CI/CD pipeline or production runtime blocks execution."

---

### Minute 4:15 – 5:00 | Architecture & Roadmap Mockups
- **Action:** Briefly click **Integrations** (`/integrations`) to show Hugging Face connector, Cloud KMS, and CI/CD GitHub Action.
- **Action:** Hover over or click **Runtime Guard** (`/preview/runtime`) and **Agent Security** (`/preview/agents`).
- **Say:**
  > "Our MVP covers ingestion, scanning, AI-BOM generation, and cryptographic attestation. For the future, we have architectural mockups for post-deployment runtime activation drift and autonomous agent tool-call policy gates."
- **Closing Statement:**
  > "Traceon ensures that what you tested is cryptographically identical to what you run. An attestation is evidence, and deterministic checks decide. Thank you!"
