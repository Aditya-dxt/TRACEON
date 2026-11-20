# Likely Judge Questions & Honest Answers

### Q1: Does Traceon guarantee that an approved model is 100% safe from all backdoors?
**Honest Answer:**  
No, and we explicitly never make that claim. An attestation is cryptographic evidence of what was checked, not a mathematical proof of absolute safety. Traceon deterministically guarantees that known deny-listed opcodes, malformed headers, and weight outliers beyond statistical thresholds are identified, and that the artifact deployed in production is byte-for-byte identical to the one inspected. Sophisticated, novel clean-label backdoors remain an active research challenge in AI safety.

---

### Q2: Why not just use an LLM like Gemini to inspect the model and decide if it's malicious?
**Honest Answer:**  
Because LLMs are probabilistic, non-deterministic, and susceptible to hallucination or prompt injection. Relying on an LLM to decide a security verdict introduces fatal variance. At Traceon, our rule is absolute: **Deterministic checks decide; the LLM explains.** Our scanner uses mathematical opcode parsing, byte offsets, and statistical thresholds to render the BLOCK/QUARANTINE/APPROVE decision. Gemini is used solely to generate clear explanations for human analysts reviewing model cards and bytecode.

---

### Q3: How do you handle scan performance on massive 70B+ parameter models?
**Honest Answer:**  
Our stated performance target is under 2 minutes scan latency and under 1% false positives—these are engineering goals, not completed benchmarks for all sizes. For Safetensors, header validation takes milliseconds because we only parse the initial JSON metadata buffer without reading tens of gigabytes of raw float tensors into memory. For deep weight statistical diffing on 70B models, we perform layer-wise subsampling to stay within memory limits inside our Cloud Run sandbox.

---

### Q4: Are Runtime Monitoring and Agent Security live in this MVP?
**Honest Answer:**  
No. In our dashboard, Runtime Monitoring and Agent Security are clearly labeled as **"Preview / Mockup"**. Our live MVP focuses strictly on the supply chain entry gate: model ingestion, deterministic opcode scanning, Safetensors verification, CycloneDX 1.7 AI-BOM generation, Cloud KMS in-toto attestation, and CI/CD verification. Post-deployment runtime guardrails are on our active roadmap.

---

### Q5: What happens if an attacker modifies a single byte in the model file after you scan it?
**Honest Answer:**  
The verification fails immediately. Because our Cloud KMS attestation binds directly to the SHA-256 cryptographic digest of the exact file scanned, modifying even a single bit or byte yields a completely different digest. When the deployment worker or CI/CD action calls `POST /v1/verify`, the mismatch is flagged and release is blocked. We demo this live with our 1-byte tamper simulation.
