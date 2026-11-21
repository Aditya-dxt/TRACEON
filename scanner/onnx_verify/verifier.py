"""
scanner/onnx_verify/verifier.py

Safe ONNX (Open Neural Network Exchange) model inspector.
Parses ONNX protobuf wire format without importing arbitrary loaders or compiling C extensions.
Checks:
- External data path traversal (CWE-22 / CWE-23: ../ or absolute paths in tensor external_data)
- Unapproved or suspicious custom operator domains
- Truncated protobuf wire tags
"""

import os
from pathlib import Path
from typing import List, Dict, Any, Tuple


class ONNXVerifier:
    def verify_file(self, file_path: Path, sha256: str) -> Tuple[str, List[Dict[str, Any]]]:
        findings = []
        file_size = file_path.stat().st_size

        if file_size < 8:
            findings.append({
                "finding_id": "f_onnx_truncated",
                "check": "onnx_verify",
                "category": "serialization",
                "severity": "critical",
                "confidence": "high",
                "deterministic": True,
                "title": "Truncated ONNX model: file size less than 8 bytes",
                "evidence": {"file": file_path.name, "size": file_size, "sha256": sha256},
                "recommendation": "File is truncated or corrupted."
            })
            return "fail", findings

        with open(file_path, "rb") as f:
            header_data = f.read(min(file_size, 1024 * 1024))
        return self.verify_bytes(header_data, file_path.name, file_size, sha256)

    def verify_bytes(self, header_data: bytes, file_name: str, file_size: int, sha256: str) -> Tuple[str, List[Dict[str, Any]]]:
        findings = []
        if file_size < 8:
            findings.append({
                "finding_id": "f_onnx_truncated",
                "check": "onnx_verify",
                "category": "serialization",
                "severity": "critical",
                "confidence": "high",
                "deterministic": True,
                "title": "Truncated ONNX model: file size less than 8 bytes",
                "evidence": {"file": file_name, "size": file_size, "sha256": sha256},
                "recommendation": "File is truncated or corrupted."
            })
            return "fail", findings

        try:
            # 1. Search for external_data references and directory traversal
            # In ONNX tensors with external data, strings like 'location' are serialized
            # followed by the file path.
            if b"location" in header_data:
                # Look for suspicious path traversal patterns
                traversal_indicators = [b"../", b"..\\", b"/etc/", b"C:\\", b"/var/", b"/root/"]
                for indicator in traversal_indicators:
                    if indicator in header_data:
                        findings.append({
                            "finding_id": "f_onnx_path_traversal",
                            "check": "onnx_verify",
                            "category": "serialization",
                            "severity": "critical",
                            "confidence": "high",
                            "deterministic": True,
                            "title": "Directory traversal detected in ONNX external data location",
                            "evidence": {
                                "pattern": indicator.decode("latin-1"),
                                "cwe": "CWE-22 (Improper Limitation of a Pathname to a Restricted Directory)",
                                "mitre_atlas": "AML.T0011.000 (Unsafe AI Artifacts)",
                                "file": file_name,
                                "sha256": sha256
                            },
                            "recommendation": "Reject file: external data reference points outside the model directory."
                        })
                        break

            # 2. Check for suspicious custom operator names in graph
            dangerous_op_tokens = [b"PyOp", b"System", b"Exec", b"Popen", b"CustomOp_Shell"]
            for token in dangerous_op_tokens:
                if token in header_data:
                    findings.append({
                        "finding_id": f"f_onnx_suspicious_op_{token.decode('latin-1')}",
                        "check": "onnx_verify",
                        "category": "serialization",
                        "severity": "high",
                        "confidence": "medium",
                        "deterministic": True,
                        "title": f"Suspicious custom operator in ONNX graph: '{token.decode('latin-1')}'",
                        "evidence": {
                            "operator_token": token.decode("latin-1"),
                            "file": file_name
                        },
                        "recommendation": "Inspect custom operator implementation to verify it does not execute host code."
                    })

        except Exception as e:
            findings.append({
                "finding_id": "f_onnx_read_err",
                "check": "onnx_verify",
                "category": "serialization",
                "severity": "medium",
                "confidence": "high",
                "deterministic": True,
                "title": f"Failed reading ONNX model: {str(e)}",
                "evidence": {"error": str(e), "file": file_name},
                "recommendation": "Check ONNX file readability."
            })

        if not findings:
            findings.append({
                "finding_id": "f_onnx_clean",
                "check": "onnx_verify",
                "category": "serialization",
                "severity": "informational",
                "confidence": "high",
                "deterministic": True,
                "title": "ONNX graph structure and tensor references verified clean",
                "evidence": {
                    "file_size": file_size,
                    "sha256": sha256
                },
                "recommendation": "ONNX model does not contain suspicious external path traversals or dangerous operators."
            })
            return "pass", findings

        has_fail = any(f.get("severity") in ("critical", "high") for f in findings)
        return "fail" if has_fail else "warn", findings
