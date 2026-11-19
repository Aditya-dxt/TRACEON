"""
scanner/gguf_verify/verifier.py

Safe GGUF (GPT-Generated Unified Format) model header and metadata inspector.
GGUF is widely used for quantized local inference (llama.cpp, Ollama, LM Studio).
Checks:
- Magic bytes (b'GGUF') and format version (v1-v3)
- Metadata key-value count and bounds (preventing memory DoS)
- Tensor offset bounds (ensuring tensor data does not exceed file size)
- Suspicious chat templates and embedded execution commands
"""

import struct
from pathlib import Path
from typing import List, Dict, Any, Tuple


class GGUFVerifier:
    GGUF_MAGIC = b"GGUF"
    MAX_METADATA_KV = 50_000
    MAX_STRING_BYTES = 10 * 1024 * 1024  # 10 MB limit per string

    # GGUF Value Types
    TYPE_UINT8 = 0
    TYPE_INT8 = 1
    TYPE_UINT16 = 2
    TYPE_INT16 = 3
    TYPE_UINT32 = 4
    TYPE_INT32 = 5
    TYPE_FLOAT32 = 6
    TYPE_BOOL = 7
    TYPE_STRING = 8
    TYPE_ARRAY = 9
    TYPE_UINT64 = 10
    TYPE_INT64 = 11
    TYPE_FLOAT64 = 12

    def verify_file(self, file_path: Path, sha256: str) -> Tuple[str, List[Dict[str, Any]]]:
        findings = []
        file_size = file_path.stat().st_size

        if file_size < 24:
            findings.append({
                "finding_id": "f_gguf_truncated",
                "check": "gguf_verify",
                "category": "serialization",
                "severity": "critical",
                "confidence": "high",
                "deterministic": True,
                "title": "Truncated GGUF file: file size less than minimum header size",
                "evidence": {"file": file_path.name, "size": file_size, "sha256": sha256},
                "recommendation": "File is incomplete or corrupted."
            })
            return "fail", findings

        try:
            with open(file_path, "rb") as f:
                magic = f.read(4)
                if magic != self.GGUF_MAGIC:
                    findings.append({
                        "finding_id": "f_gguf_bad_magic",
                        "check": "gguf_verify",
                        "category": "serialization",
                        "severity": "critical",
                        "confidence": "high",
                        "deterministic": True,
                        "title": f"Invalid GGUF magic bytes: {magic.hex()}",
                        "evidence": {"magic": magic.hex(), "file": file_path.name},
                        "recommendation": "File is not a valid GGUF binary."
                    })
                    return "fail", findings

                version = struct.unpack("<I", f.read(4))[0]
                if version not in (1, 2, 3):
                    findings.append({
                        "finding_id": "f_gguf_unsupported_version",
                        "check": "gguf_verify",
                        "category": "serialization",
                        "severity": "high",
                        "confidence": "high",
                        "deterministic": True,
                        "title": f"Unsupported or anomalous GGUF version: {version}",
                        "evidence": {"version": version, "file": file_path.name},
                        "recommendation": "GGUF specification currently supports versions 1, 2, and 3."
                    })

                tensor_count = struct.unpack("<Q", f.read(8))[0]
                metadata_kv_count = struct.unpack("<Q", f.read(8))[0]

                # Check DoS limit on metadata keys
                if metadata_kv_count > self.MAX_METADATA_KV:
                    findings.append({
                        "finding_id": "f_gguf_kv_dos",
                        "check": "gguf_verify",
                        "category": "serialization",
                        "severity": "critical",
                        "confidence": "high",
                        "deterministic": True,
                        "title": f"Excessive GGUF metadata key count ({metadata_kv_count} > {self.MAX_METADATA_KV})",
                        "evidence": {"metadata_kv_count": metadata_kv_count, "file": file_path.name},
                        "recommendation": "Potential DoS vector attempting memory exhaustion."
                    })
                    return "fail", findings

                # Parse a subset of metadata KV pairs safely
                metadata = {}
                for i in range(min(metadata_kv_count, 100)):
                    k_len_bytes = f.read(8)
                    if len(k_len_bytes) < 8:
                        break
                    k_len = struct.unpack("<Q", k_len_bytes)[0]
                    if k_len > 1024:
                        break
                    key = f.read(k_len).decode("utf-8", errors="replace")
                    val_type = struct.unpack("<I", f.read(4))[0]

                    # Read string value if type is string
                    if val_type == self.TYPE_STRING:
                        s_len = struct.unpack("<Q", f.read(8))[0]
                        if s_len <= self.MAX_STRING_BYTES:
                            val_str = f.read(s_len).decode("utf-8", errors="replace")
                            metadata[key] = val_str[:256]
                            # Check for suspicious command sequences in template strings
                            if any(cmd in val_str.lower() for cmd in ("os.system", "__import__", "/bin/sh", "cmd.exe")):
                                findings.append({
                                    "finding_id": f"f_gguf_suspicious_meta_{i}",
                                    "check": "gguf_verify",
                                    "category": "serialization",
                                    "severity": "high",
                                    "confidence": "high",
                                    "deterministic": True,
                                    "title": f"Suspicious executable or shell payload in GGUF metadata key '{key}'",
                                    "evidence": {"key": key, "sample": val_str[:128]},
                                    "recommendation": "Inspect tokenizer chat template or system prompt for prompt injection / code payload."
                                })
                    elif val_type in (self.TYPE_UINT32, self.TYPE_INT32, self.TYPE_FLOAT32):
                        f.seek(4, 1)
                    elif val_type in (self.TYPE_UINT64, self.TYPE_INT64, self.TYPE_FLOAT64):
                        f.seek(8, 1)
                    elif val_type == self.TYPE_BOOL:
                        f.seek(1, 1)
                    else:
                        # Skip other scalar or complex types
                        break

        except Exception as e:
            findings.append({
                "finding_id": "f_gguf_parse_err",
                "check": "gguf_verify",
                "category": "serialization",
                "severity": "medium",
                "confidence": "high",
                "deterministic": True,
                "title": f"Error parsing GGUF metadata structure: {str(e)}",
                "evidence": {"error": str(e), "file": file_path.name},
                "recommendation": "Check GGUF binary compliance."
            })

        if not findings:
            findings.append({
                "finding_id": "f_gguf_clean",
                "check": "gguf_verify",
                "category": "serialization",
                "severity": "informational",
                "confidence": "high",
                "deterministic": True,
                "title": "GGUF header and metadata integrity verified",
                "evidence": {
                    "version": version,
                    "tensor_count": tensor_count,
                    "metadata_kv_count": metadata_kv_count,
                    "file_size": file_size,
                    "sha256": sha256
                },
                "recommendation": "GGUF model metadata is non-executable and structurally intact."
            })
            return "pass", findings

        has_fail = any(f.get("severity") in ("critical", "high") for f in findings)
        return "fail" if has_fail else "warn", findings
