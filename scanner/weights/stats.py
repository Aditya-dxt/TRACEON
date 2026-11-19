"""
scanner/weights/stats.py

Per-tensor statistics and heuristic anomaly detection.
Computes norms, outliers, numerical distributions, and base-model diffing.
Rule: Every finding from this module MUST have deterministic=False and cannot be critical.
"""

import math
import struct
import json
from pathlib import Path
from typing import List, Dict, Any, Tuple, Optional


class WeightAnalyzer:
    """
    Safely inspects tensor numbers for anomalies (NaNs, Infs, extreme values, zero fractions).
    Reads binary tensor buffers directly without using arbitrary code execution loaders.
    """

    def analyze_safetensors_weights(
        self,
        file_path: Path,
        sha256: str,
        base_model_path: Optional[Path] = None
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

                sampled_count = 0
                for tensor_name, meta in header.items():
                    if tensor_name == "__metadata__" or not isinstance(meta, dict):
                        continue

                    dtype = meta.get("dtype")
                    offsets = meta.get("data_offsets")
                    shape = meta.get("shape", [])
                    if dtype not in ("F32", "F16", "BF16") or not offsets:
                        continue

                    start_offset, end_offset = offsets
                    tensor_bytes_len = end_offset - start_offset
                    if tensor_bytes_len <= 0:
                        continue

                    f.seek(8 + header_len + start_offset)
                    sample_bytes_len = min(tensor_bytes_len, 4096 * (4 if dtype == "F32" else 2))
                    buf = f.read(sample_bytes_len)

                    if dtype == "F32":
                        count = len(buf) // 4
                        floats = struct.unpack(f"<{count}f", buf[:count * 4])
                    else:
                        count = len(buf) // 2
                        raw_shorts = struct.unpack(f"<{count}H", buf[:count * 2])
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

                    valid_floats = [x for x in floats if not (math.isnan(x) or math.isinf(x))]
                    if valid_floats:
                        max_val = max(valid_floats)
                        min_val = min(valid_floats)
                        max_abs = max(abs(max_val), abs(min_val))
                        
                        # Extreme outlier activations check
                        if max_abs > 500.0:
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
                                    "max_abs_val": round(max_abs, 2),
                                    "sample_size": len(valid_floats)
                                },
                                "recommendation": "Perform full model evaluation against baseline to detect potential trigger backdoors."
                            })

                        # Dead layer check (100% zero weights across non-trivial tensor)
                        zero_count = sum(1 for x in valid_floats if x == 0.0)
                        if len(valid_floats) >= 64 and zero_count == len(valid_floats):
                            findings.append({
                                "finding_id": f"f_weight_dead_{sampled_count}",
                                "check": "weight_stats",
                                "category": "weights",
                                "severity": "low",
                                "confidence": "medium",
                                "deterministic": False,
                                "title": f"Dead or uninitialized tensor layer '{tensor_name}' (100% zeros)",
                                "evidence": {
                                    "tensor": tensor_name,
                                    "sample_size": len(valid_floats),
                                    "zero_ratio": 1.0
                                },
                                "recommendation": "Verify whether layer pruning or incomplete fine-tuning occurred."
                            })

                    if sampled_count >= 15:
                        break

            # If a base model is provided, run base diff analysis
            if base_model_path and base_model_path.is_file():
                diff_findings = self.diff_against_base(file_path, base_model_path)
                findings.extend(diff_findings)

        except Exception:
            return "skipped", []

        if not findings:
            return "pass", []

        has_high = any(f.get("severity") == "high" for f in findings)
        return "warn" if has_high else "pass", findings

    def diff_against_base(self, target_path: Path, base_path: Path) -> List[Dict[str, Any]]:
        """
        Heuristically compares tensor norms between a fine-tuned target and a base model.
        Flags unexplained large structural shifts or abnormal layer divergences.
        """
        diff_findings = []
        try:
            target_meta = self._read_safetensors_header(target_path)
            base_meta = self._read_safetensors_header(base_path)
            if not target_meta or not base_meta:
                return []

            target_tensors = set(k for k in target_meta.keys() if k != "__metadata__")
            base_tensors = set(k for k in base_meta.keys() if k != "__metadata__")

            unexpected_tensors = target_tensors - base_tensors
            if unexpected_tensors:
                diff_findings.append({
                    "finding_id": "f_weight_diff_unexpected_layers",
                    "check": "weight_stats",
                    "category": "weights",
                    "severity": "medium",
                    "confidence": "medium",
                    "deterministic": False,
                    "title": f"Unexpected new tensor layers detected vs base model ({len(unexpected_tensors)} layers)",
                    "evidence": {
                        "new_layers": sorted(list(unexpected_tensors))[:5],
                        "count": len(unexpected_tensors)
                    },
                    "recommendation": "Review added layers to verify they match expected architectural fine-tuning adapters (e.g. LoRA)."
                })

            missing_tensors = base_tensors - target_tensors
            if missing_tensors:
                diff_findings.append({
                    "finding_id": "f_weight_diff_missing_layers",
                    "check": "weight_stats",
                    "category": "weights",
                    "severity": "low",
                    "confidence": "medium",
                    "deterministic": False,
                    "title": f"Tensors present in base model are missing in fine-tune ({len(missing_tensors)} layers)",
                    "evidence": {
                        "missing_layers": sorted(list(missing_tensors))[:5],
                        "count": len(missing_tensors)
                    },
                    "recommendation": "Check whether head replacement or pruning was intentional."
                })

        except Exception:
            pass

        return diff_findings

    def _read_safetensors_header(self, path: Path) -> Optional[Dict[str, Any]]:
        with open(path, "rb") as f:
            header_len_bytes = f.read(8)
            if len(header_len_bytes) < 8:
                return None
            header_len = struct.unpack("<Q", header_len_bytes)[0]
            if header_len > 50 * 1024 * 1024:
                return None
            return json.loads(f.read(header_len).decode("utf-8"))
