"""
scanner/weights/stats.py

Per-tensor statistics and heuristic anomaly detection.
Computes norms, outliers, and numerical distributions.
Rule: Every finding from this module MUST have deterministic=False and cannot be critical.
"""

import math
import struct
import json
from pathlib import Path
from typing import List, Dict, Any, Tuple


class WeightAnalyzer:
    """
    Safely inspects tensor numbers for anomalies (NaNs, Infs, extreme values, zero fractions).
    Reads binary tensor buffers directly without using arbitrary code execution loaders.
    """

    def analyze_safetensors_weights(
        self,
        file_path: Path,
        sha256: str
    ) -> Tuple[str, List[Dict[str, Any]]]:
        findings = []

        try:
            with open(file_path, "rb") as f:
                header_len_bytes = f.read(8)
                if len(header_len_bytes) < 8:
                    return "skipped", findings

                header_len = struct.unpack("<Q", header_len_bytes)[0]
                if header_len > 50 * 1024 * 1024:
                    return "skipped", findings

                raw_header = f.read(header_len)
                header = json.loads(raw_header.decode("utf-8"))

                # Read up to 5 tensors for statistical sampling to keep scanning fast and memory-safe
                sampled_count = 0
                for tensor_name, meta in header.items():
                    if tensor_name == "__metadata__" or not isinstance(meta, dict):
                        continue

                    dtype = meta.get("dtype")
                    offsets = meta.get("data_offsets")
                    if dtype not in ("F32", "F16", "BF16") or not offsets:
                        continue

                    start_offset, end_offset = offsets
                    tensor_bytes_len = end_offset - start_offset
                    if tensor_bytes_len <= 0:
                        continue

                    # Read a sample of the tensor bytes (up to 4096 elements)
                    f.seek(8 + header_len + start_offset)
                    sample_bytes_len = min(tensor_bytes_len, 4096 * (4 if dtype == "F32" else 2))
                    buf = f.read(sample_bytes_len)

                    if dtype == "F32":
                        count = len(buf) // 4
                        floats = struct.unpack(f"<{count}f", buf[:count * 4])
                    else:
                        # For F16 / BF16 approximate by unpack unsigned shorts
                        count = len(buf) // 2
                        raw_shorts = struct.unpack(f"<{count}H", buf[:count * 2])
                        # Convert half-float to float if possible, or rough check
                        floats = [float(s) / 32768.0 for s in raw_shorts]

                    if not floats:
                        continue

                    sampled_count += 1
                    nan_count = sum(1 for x in floats if math.isnan(x))
                    inf_count = sum(1 for x in floats if math.isinf(x))

                    if nan_count > 0 or inf_count > 0:
                        findings.append({
                            "finding_id": f"f_weight_nan_{sampled_count}",
                            "check": "weight_stats",
                            "category": "weights",
                            "severity": "high",
                            "confidence": "medium",
                            "deterministic": False,
                            "title": f"Corrupted or anomalous numerical values (NaN/Inf) in tensor '{tensor_name}'",
                            "evidence": {
                                "tensor": tensor_name,
                                "nan_count": nan_count,
                                "inf_count": inf_count,
                                "sample_size": len(floats)
                            },
                            "recommendation": "Review checkpoint training history; NaNs or Infs indicate numerical divergence or sabotage."
                        })

                    # Check for extreme outlier activations (e.g. max magnitude > 1000 in normalized layers)
                    valid_floats = [x for x in floats if not (math.isnan(x) or math.isinf(x))]
                    if valid_floats:
                        max_val = max(valid_floats)
                        min_val = min(valid_floats)
                        if max(abs(max_val), abs(min_val)) > 500.0:
                            findings.append({
                                "finding_id": f"f_weight_outlier_{sampled_count}",
                                "check": "weight_stats",
                                "category": "weights",
                                "severity": "medium",
                                "confidence": "medium",
                                "deterministic": False,
                                "title": f"Unusually large weight magnitude in tensor '{tensor_name}'",
                                "evidence": {
                                    "tensor": tensor_name,
                                    "max_abs_val": round(max(abs(max_val), abs(min_val)), 2),
                                    "sample_size": len(valid_floats)
                                },
                                "recommendation": "Perform full model evaluation against baseline to detect potential trigger backdoors."
                            })

                    if sampled_count >= 10:
                        break

        except Exception as e:
            # Weight scanning is non-fatal; never raises
            return "skipped", []

        if not findings:
            return "pass", []
        
        has_high = any(f.get("severity") == "high" for f in findings)
        return "warn" if has_high else "pass", findings
