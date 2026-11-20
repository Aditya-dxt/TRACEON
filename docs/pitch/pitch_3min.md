# Traceon: 3-Minute Competition Pitch

**Team:** DeepTrace AI  
**Presenter:** Aadya Pandey (Product & Design Lead) / Team DeepTrace AI

---

### [0:00 - 0:45] The Hook: The AI Supply Chain Blindspot
"In software engineering, we spent a decade securing the supply chain: npm audits, SBOMs, code signing. But in AI, developers download gigabyte-scale black-box model files directly from public registries like Hugging Face without verification.

In July 2026, researchers demonstrated that weaponized serialized pickle files on public hubs could bypass standard firewalls to gain remote shell access within enterprise Kubernetes clusters. Even with Safetensors, stealth trigger backdoors can survive unseen inside deep neural network weights.

Today, enterprise AI teams deploy models on blind trust."

---

### [0:45 - 1:45] The Solution: Traceon
"Traceon is the end-to-end AI supply chain security platform. We bring rigorous cryptographic provenance and deterministic opcode inspection to machine learning models.

Traceon works on three foundational pillars:

1. **Deterministic Static Opcode Inspection:**
   We never execute untrusted weights. Aditya's scanner disassembles pickle opcodes and Safetensors headers inside a zero-egress sandbox, identifying deny-listed system calls down to the exact byte offset.
2. **CycloneDX 1.7 AI-BOM Generation:**
   We construct a complete lineage graph—linking base models, fine-tuning datasets, training parameters, and framework libraries into standard CycloneDX 1.7 JSON.
3. **Hardware-Backed Cryptographic Attestation:**
   Vaibhav's backend policy engine binds the model digest and BOM digest into an in-toto statement signed via Google Cloud KMS. If a single byte in the weights changes between scanning and deployment, our CI/CD GitHub Action fails the release pipeline."

---

### [1:45 - 2:30] The Secret Sauce: The LLM Explains, Deterministic Checks Decide
"A lot of AI security startups make a fatal mistake: they ask an LLM if a model is safe. LLMs hallucinate, and probabilistic checks fail against adversarial evasion.

Our philosophy is crystal clear:
- **Deterministic checks decide.** Mathematical byte disassembly and hash verifications produce the verdict: BLOCK, QUARANTINE, CONDITIONAL, or APPROVE.
- **The LLM explains.** Gemini translates dense opcode offsets and tensor anomalies into clear context for security engineers.
- **An attestation is evidence, not proof of safety.** We provide verifiable cryptographic guarantees of what was inspected."

---

### [2:30 - 3:00] Team & Market Traction
"Our team is uniquely built to deliver this:
- **Aditya Dixit (AI & Security Lead, CEO):** Architected the opcode scanner, Safetensors verifier, and weight statistics engine.
- **Vaibhav Tripathi (CTO, Backend & Platform):** Built our FastAPI policy engine, Cloud KMS in-toto attestation, and sandboxed runner.
- **Aadya Pandey (Product & Design Lead):** Designed our Quiet Luxury user experience, CycloneDX AI-BOM explorer, and developer verification tooling.

With Traceon, AI teams stop hoping their models are clean—they verify them cryptographically before a single token is served."
