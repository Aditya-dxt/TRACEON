# Slide 2: Real-World Incident Sources & Empirical Background

### 1. Hugging Face Malicious Model Repositories (July 2026 & Ongoing Research)
- **Incident Summary:** Security researchers identified multiple publicly hosted model weights on the Hugging Face hub containing embedded Python pickle exploits designed to establish reverse shells upon invocation of `torch.load()`.
- **Primary Attack Vector:** Python pickle deserialization (`posix.system`, `subprocess.Popen`, `eval`, `builtins.__import__`).
- **Impact:** Automated CI/CD pipelines pulling unverified community checkpoints executed arbitrary commands inside enterprise container environments with network access.
- **Reference Publications & Trackers:**
  - JFrog Security Research: "Malicious AI Models Discovered on Hugging Face Executing Code"
  - Protect AI Threat Research: "Huntr Bug Bounty Bug Reports on Arbitrary Deserialization RCE in PyTorch/Pickle"
  - Wiz Research: "AI Supply Chain Vulnerabilities & Compromised Model Checkpoints"

### 2. Backdooring Safetensors & Non-Pickle Artifacts
- **Incident Summary:** While Safetensors mitigates arbitrary executable code by using strict JSON headers and flat binary buffers, malicious actors can inject weight poisons, activation trojans, or malformed header offsets designed to trigger out-of-bounds memory reads or targeted classification degradation.
- **Traceon Countermeasure:** 
  - Safetensors header validation: strict checks ensuring `data_offsets` do not overlap or exceed file boundaries.
  - Weight outlier detection: statistical baseline comparison to detect perturbed layer activations.

### 3. Untrusted Training Corpus & Dataset Poisoning
- **Incident Summary:** Ingestion of open datasets with embedded malicious Python preprocessing scripts, hash mismatches, or altered labels.
- **Traceon Countermeasure:**
  - Dataset Guard checks file types by magic bytes, flags unexpected executable scripts, and checks cryptographic hash integrity against signed manifests.

### Content Compliance Rule Notice:
- *Traceon does not make absolute claims that it makes AI safe or finds every backdoor. An attestation is evidence of cryptographic state, not absolute proof of safety.*
