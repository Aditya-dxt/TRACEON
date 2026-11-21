# 🧪 Traceon Scanner: Benchmark & False-Positive Review

> **Author**: Aditya Dixit (CEO, AI & Security Engineering Lead)  
> **Module**: `scanner/`  
> **Status**: Verified against synthetic corpus & benign sample models  
> **Last Updated**: November 2026  

---

## 1. Evaluation Methodology

In accordance with Traceon's defensive engineering guidelines, all testing is conducted using **controlled, harmless, synthetic artifacts**. No weaponized malware or uncontrolled payloads are introduced into test pipelines.

### Test Corpus Composition

| Fixture Path | Format | Size | Purpose / Injected Condition | Expected Result |
| :--- | :--- | :--- | :--- | :---: |
| `scanner/corpus/evil.bin` | Pickle (v2) | 53 B | Opcode calling `posix.system` | 🔴 `CRITICAL` finding (`fail`) |
| `scanner/corpus/pytorch_evil.pt` | PyTorch ZIP | 385 B | Nested `archive/data.pkl` with `posix.system` | 🔴 `CRITICAL` finding (`fail`) |
| `scanner/corpus/clean.pkl` | Pickle (v4) | 154 B | Benign primitives (`dict`, `float`, `list`) | 🟢 `PASS` (0 findings) |
| `scanner/corpus/pytorch_clean.pt` | PyTorch ZIP | 435 B | PyTorch ZIP with safe state dictionary | 🟢 `PASS` (0 findings) |
| `scanner/corpus/valid.safetensors` | Safetensors | 144 B | Valid header and memory offsets | 🟢 `PASS` (informational only) |
| `scanner/corpus/malformed.safetensors` | Safetensors | 90 B | Offset points to `100,000` (past EOF) | 🔴 `CRITICAL` finding (`fail`) |
| `scanner/corpus/clean.gguf` | GGUF (v3) | 260 B | Valid magic `GGUF`, schema, and benign chat template | 🟢 `PASS` (0 findings) |
| `scanner/corpus/malformed.gguf` | GGUF (v3) | 280 B | Embedded Jinja2 chat template containing shell injection | 🔴 `CRITICAL` finding (`fail`) |
| `scanner/corpus/clean.onnx` | ONNX | 170 B | Valid protobuf graph and safe standard operators | 🟢 `PASS` (0 findings) |
| `scanner/corpus/traversal.onnx` | ONNX | 195 B | External tensor location with `../../etc/passwd` path traversal | 🔴 `CRITICAL` finding (`fail`) |
| `scanner/corpus/dataset_script/` | Directory | 165 B | Unexpected `.py` script inside dataset | 🟡 `HIGH` finding (`fail`) |
| `scanner/corpus/hash_mismatch/` | Directory | 182 B | File digest differs from `manifest.json` | 🟡 `HIGH` finding (`fail`) |

---

## 2. Threat Intelligence & Taxonomy Alignment

All scanner findings are enriched with industry-standard taxonomy identifiers for SIEM/SOC and compliance automation:
- **MITRE ATLAS**:
  - `AML.T0010`: ML Supply Chain Compromise (backdoored model weights, rogue callables)
  - `AML.T0011.000`: Evasion via Serialization Manipulation (corrupted headers, hidden offsets)
  - `AML.T0048`: Adversarial Data Poisoning (dataset scripts, manifest mismatches)
- **CWE (Common Weakness Enumeration)**:
  - `CWE-502`: Deserialization of Untrusted Data (arbitrary opcode execution in pickles)
  - `CWE-78`: OS Command Injection (`system`, `popen`, `exec` invocation)
  - `CWE-22`: Improper Limitation of a Pathname to a Restricted Directory (external tensor directory traversal)
  - `CWE-94`: Improper Control of Generation of Code (code injection in chat templates)
  - `CWE-125`: Out-of-bounds Read (tensor byte offsets past file end)
- **MITRE ATT&CK Enterprise**:
  - `T1059.006`: Command and Scripting Interpreter: Python
  - `T1041`: Exfiltration Over C2 Channel
  - `T1070.004`: File Deletion / Defense Evasion

---

## 3. Benchmark Results

### Detection Rate on Known Malicious Patterns
- **Pickle Opcode Scanning**: **100% detection (3/3)** on tested synthetic samples (`evil.bin`, `pytorch_evil.pt`, and Protocol 4 `STACK_GLOBAL` builtins import).
- **Safetensors Boundary Verification**: **100% rejection (3/3)** on invalid offsets, header truncation, and 10GB header DoS attack.
- **Zero-Download HTTP Range Streaming**: **100% accuracy (6/6)** parsing remote Safetensors, PyTorch ZIP, GGUF, and Pickle files without downloading tensor weights.
- **GGUF Structure & Template Verification**: **100% detection (2/2)** on valid headers vs. dangerous template injection payloads.
- **ONNX External Tensor Verification**: **100% detection (2/2)** on valid graphs vs. path traversal `../../` arbitrary file access.
- **Dataset Guard**: **100% detection (4/4)** on unexpected scripts (`.py`), manifest hash mismatches, corrupted JSONL lines, and spoofed Parquet headers.

### False-Positive Rate on Benign Samples
- **Clean Pickle (`clean.pkl`)**: 0 findings above informational.
- **Clean PyTorch Checkpoint (`pytorch_clean.pt`)**: 0 findings above informational.
- **Valid Safetensors (`valid.safetensors`)**: 1 informational finding confirming valid non-executable structure.
- **Clean GGUF (`clean.gguf`)**: 0 findings above informational.
- **Clean ONNX (`clean.onnx`)**: 0 findings above informational.
- **Target Goal**: Under 1.0% false positives on standard Hugging Face top-100 open checkpoints (labeled as a performance target, not a verified production claim across all unmeasured models).

### Latency & Performance Measurements
- **Zero-Download Bandwidth Savings**: **> 99.9% network bandwidth saved** on remote Safetensors models (parses header in < 50 KB instead of transferring gigabytes).
- **Synthetic Corpus Scan Time**: Average `< 15ms` per file (static opcode analysis and streaming SHA-256).
- **Test Suite Execution Time**: **30 unit, red-team, and remote streaming tests completed in 1.27 seconds** via `pytest`.
- **Target Goal**: `< 2 minutes` scan time on multi-gigabyte checkpoints running inside no-egress Cloud Run sandboxes.

---

## 3. Red-Team & Evasion Findings

During internal red-teaming of the scanner, three evasion vectors were analyzed and resolved:

1. **Protocol 4 `STACK_GLOBAL` Stack Order**:
   - *Vulnerability*: In Python pickle protocol 4, `STACK_GLOBAL` pops `callable_name` first, followed by `module_name`. An initial naive implementation popped them in reverse order, which inverted module/callable pairings.
   - *Fix*: Corrected stack operand ordering in `scanner/pickle_scan/scanner.py`. Verified with `test_redteam_stack_global_obfuscation`.

2. **Oversized Header DoS**:
   - *Vulnerability*: A malicious Safetensors file could declare an 8GB header length, causing workers to allocate excessive memory before reading tensor data.
   - *Fix*: Enforced `MAX_HEADER_SIZE_BYTES = 100MB`. Headers exceeding this threshold are immediately rejected with a critical finding.

3. **Zip Slip Resilience**:
   - *Vulnerability*: PyTorch zip checkpoints could contain path traversal filenames (e.g., `../../target.txt`).
   - *Fix*: The scanner operates strictly in memory via `zipfile.ZipFile.open()` streams; no files are extracted or written to the host filesystem. Verified with `test_redteam_zip_slip_resilience`.

---

## 4. Honest Limits (Boundary Declarations)

As stated in the Traceon master blueprint:
1. **No absolute claims**: The scanner detects known serialization risks, dangerous callables, malformed memory layouts, and anomalous tensor distributions. It cannot prove that an arbitrary machine learning model contains zero backdoors.
2. **Deterministic vs. Probabilistic**:
   - Opcode, header, and hash checks are **deterministic** (`deterministic: true`).
   - Weight anomaly and outlier checks are **probabilistic** (`deterministic: false`) and never assign a `critical` severity or automatic block.
3. **LLMs Explain Only**: The Gemini model-card explainer (`scanner/explain/`) provides descriptive context on license terms and datasets. It is strictly forbidden from voting on or deciding security verdicts.
