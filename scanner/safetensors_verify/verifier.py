"""
scanner/safetensors_verify/verifier.py

Safe Safetensors format verifier.
Validates header JSON, dtypes, tensor shapes against byte lengths,
and verifies data offsets do not overlap, corrupt, or exceed file size.
"""

import json
import struct
from pathlib import Path
from typing import List, Dict, Any, Tuple
from functools import reduce
import operator

# Supported Safetensors dtypes and their byte sizes
DTYPE_BYTE_SIZES = {
    "F64": 8,
    "F32": 4,
    "F16": 2,
    "BF16": 2,
    "I64": 8,
    "I32": 4,
    "I16": 2,
    "I8": 1,
    "U64": 8,
    "U32": 4,
    "U16": 2,
    "U8": 1,
    "BOOL": 1,
}


class SafetensorsVerifier:
    def __init__(self, max_header_bytes: int = 100 * 1024 * 1024):
        self.max_header_bytes = max_header_bytes

    def verify_file(self, file_path: Path, sha256: str) -> Tuple[str, List[Dict[str, Any]]]:
        findings = []
        file_size = file_path.stat().st_size

        if file_size < 8:
            findings.append({
                "finding_id": "f_st_too_small",
                "check": "safetensors_verify",
                "category": "serialization",
                "severity": "critical",
                "confidence": "high",
                "deterministic": True,
                "title": "Safetensors file too small (less than 8 bytes)",
                "evidence": {"file": file_path.name, "file_size": file_size, "sha256": sha256},
                "recommendation": "File is truncated or corrupted."
            })
            return "fail", findings

        with open(file_path, "rb") as f:
            header_len_bytes = f.read(8)
            header_len = struct.unpack("<Q", header_len_bytes)[0]

            if header_len <= 0 or header_len > self.max_header_bytes:
                findings.append({
                    "finding_id": "f_st_invalid_header_len",
                    "check": "safetensors_verify",
                    "category": "serialization",
                    "severity": "critical",
                    "confidence": "high",
                    "deterministic": True,
                    "title": f"Safetensors header length invalid: {header_len} bytes",
                    "evidence": {"header_len": header_len, "file_size": file_size, "sha256": sha256},
                    "recommendation": "Reject file: abnormal header length could cause resource exhaustion."
                })
                return "fail", findings

            if (8 + header_len) > file_size:
                findings.append({
                    "finding_id": "f_st_header_exceeds_eof",
                    "check": "safetensors_verify",
                    "category": "serialization",
                    "severity": "critical",
                    "confidence": "high",
                    "deterministic": True,
                    "title": "Safetensors header exceeds end of file",
                    "evidence": {
                        "header_len": header_len,
                        "file_size": file_size,
                        "needed_bytes": 8 + header_len,
                        "sha256": sha256
                    },
                    "recommendation": "File is truncated or deliberately corrupted."
                })
                return "fail", findings

            raw_header = f.read(header_len)
            try:
                header_json = json.loads(raw_header.decode("utf-8"))
            except Exception as e:
                findings.append({
                    "finding_id": "f_st_unparseable_header",
                    "check": "safetensors_verify",
                    "category": "serialization",
                    "severity": "critical",
                    "confidence": "high",
                    "deterministic": True,
                    "title": f"Safetensors header is not valid JSON: {str(e)}",
                    "evidence": {"error": str(e), "file": file_path.name, "sha256": sha256},
                    "recommendation": "Corrupted or non-compliant safetensors header."
                })
                return "fail", findings

        # Verify tensor definitions
        buffer_start = 8 + header_len
        available_buffer = file_size - buffer_start
        tensors_checked = 0
        offsets_seen = []

        for tensor_name, meta in header_json.items():
            if tensor_name == "__metadata__":
                continue

            if not isinstance(meta, dict):
                findings.append({
                    "finding_id": f"f_st_meta_{tensor_name}",
                    "check": "safetensors_verify",
                    "category": "serialization",
                    "severity": "high",
                    "confidence": "high",
                    "deterministic": True,
                    "title": f"Invalid tensor metadata entry for '{tensor_name}'",
                    "evidence": {"tensor": tensor_name, "meta": str(meta)},
                    "recommendation": "Inspect safetensors generator specification."
                })
                continue

            dtype = meta.get("dtype")
            shape = meta.get("shape")
            offsets = meta.get("data_offsets")

            if not dtype or not isinstance(shape, list) or not offsets or len(offsets) != 2:
                findings.append({
                    "finding_id": f"f_st_missing_fields_{tensor_name}",
                    "check": "safetensors_verify",
                    "category": "serialization",
                    "severity": "high",
                    "confidence": "high",
                    "deterministic": True,
                    "title": f"Malformed tensor metadata structure for '{tensor_name}'",
                    "evidence": {"tensor": tensor_name, "dtype": dtype, "shape": shape, "offsets": offsets},
                    "recommendation": "Verify metadata conforms to Safetensors spec."
                })
                continue

            start_offset, end_offset = offsets[0], offsets[1]
            if start_offset < 0 or end_offset < start_offset:
                findings.append({
                    "finding_id": f"f_st_invalid_offset_{tensor_name}",
                    "check": "safetensors_verify",
                    "category": "serialization",
                    "severity": "critical",
                    "confidence": "high",
                    "deterministic": True,
                    "title": f"Negative or inverted data offset for tensor '{tensor_name}'",
                    "evidence": {"tensor": tensor_name, "data_offsets": offsets},
                    "recommendation": "Reject file: invalid memory bounds."
                })
                continue

            if end_offset > available_buffer:
                findings.append({
                    "finding_id": f"f_st_offset_past_eof_{tensor_name}",
                    "check": "safetensors_verify",
                    "category": "serialization",
                    "severity": "critical",
                    "confidence": "high",
                    "deterministic": True,
                    "title": f"Data offset past end of file for tensor '{tensor_name}'",
                    "evidence": {
                        "tensor": tensor_name,
                        "data_offsets": offsets,
                        "available_buffer_bytes": available_buffer,
                        "declared_offset_end": end_offset,
                        "file_size": file_size,
                        "sha256": sha256,
                        "cwe": "CWE-125 (Out-of-bounds Read)",
                        "mitre_atlas": "AML.T0011.000 (Unsafe AI Artifacts)"
                    },
                    "recommendation": "Do not load this file. Offset references non-existent bytes past EOF."
                })
                continue

            # Verify size calculation: product(shape) * sizeof(dtype) == (end_offset - start_offset)
            element_count = reduce(operator.mul, shape, 1) if shape else 1
            unit_size = DTYPE_BYTE_SIZES.get(dtype)
            if unit_size:
                expected_bytes = element_count * unit_size
                actual_bytes = end_offset - start_offset
                if expected_bytes != actual_bytes:
                    findings.append({
                        "finding_id": f"f_st_size_mismatch_{tensor_name}",
                        "check": "safetensors_verify",
                        "category": "serialization",
                        "severity": "high",
                        "confidence": "high",
                        "deterministic": True,
                        "title": f"Tensor shape and dtype byte size mismatch for '{tensor_name}'",
                        "evidence": {
                            "tensor": tensor_name,
                            "expected_bytes": expected_bytes,
                            "actual_offset_bytes": actual_bytes,
                            "shape": shape,
                            "dtype": dtype
                        },
                        "recommendation": "Buffer size mismatch indicates altered or corrupt tensor."
                    })

            offsets_seen.append((start_offset, end_offset, tensor_name))
            tensors_checked += 1

        # Check for overlapping offsets
        offsets_seen.sort(key=lambda x: x[0])
        for i in range(len(offsets_seen) - 1):
            curr_start, curr_end, curr_name = offsets_seen[i]
            next_start, next_end, next_name = offsets_seen[i + 1]
            if curr_end > next_start:
                findings.append({
                    "finding_id": f"f_st_overlap_{curr_name}_{next_name}",
                    "check": "safetensors_verify",
                    "category": "serialization",
                    "severity": "critical",
                    "confidence": "high",
                    "deterministic": True,
                    "title": f"Overlapping tensor byte offsets between '{curr_name}' and '{next_name}'",
                    "evidence": {
                        "tensor1": curr_name,
                        "range1": [curr_start, curr_end],
                        "tensor2": next_name,
                        "range2": [next_start, next_end]
                    },
                    "recommendation": "Overlapping tensor buffers can lead to memory corruption."
                })

        # If clean, add informational confirmation
        if not findings:
            findings.append({
                "finding_id": "f_st_clean",
                "check": "safetensors_verify",
                "category": "serialization",
                "severity": "informational",
                "confidence": "high",
                "deterministic": True,
                "title": "Safetensors header and tensor boundary check passed",
                "evidence": {
                    "tensors_verified": tensors_checked,
                    "header_size_bytes": header_len,
                    "file_size": file_size,
                    "sha256": sha256
                },
                "recommendation": "File structure is non-executable and adheres to the Safetensors specification."
            })
            return "pass", findings

        has_failure = any(f.get("severity") in ("critical", "high") for f in findings)
        return "fail" if has_failure else "pass", findings
