"""
scanner/dataset_guard/guard.py

Dataset security inspection and integrity checks.
Detects unexpected executable scripts, checks file types by magic bytes,
validates checksums against manifests, and inspects basic CSV/JSON data structures.
"""

import os
import csv
import json
import hashlib
from pathlib import Path
from typing import List, Dict, Any, Tuple


class DatasetGuard:
    EXECUTABLE_EXTENSIONS = {
        ".py", ".sh", ".bash", ".exe", ".bin", ".elf", ".so", ".dll",
        ".bat", ".cmd", ".ps1", ".vbs", ".js", ".php"
    }

    EXECUTABLE_MAGIC_PREFIXES = [
        (b"MZ", "Windows PE Executable"),
        (b"\x7fELF", "Linux ELF Binary"),
        (b"#!", "Script Shebang"),
    ]

    def scan_directory(self, dir_path: Path) -> Tuple[str, List[Dict[str, Any]], Dict[str, Any]]:
        findings = []
        files_inspected = 0
        total_bytes = 0

        manifest_path = dir_path / "manifest.json"
        manifest_data = None
        if manifest_path.is_file():
            try:
                manifest_data = json.loads(manifest_path.read_text(encoding="utf-8"))
            except Exception as e:
                findings.append({
                    "finding_id": "f_ds_bad_manifest",
                    "check": "dataset_guard",
                    "category": "dataset",
                    "severity": "medium",
                    "confidence": "high",
                    "deterministic": True,
                    "title": f"Unparseable dataset manifest: {str(e)}",
                    "evidence": {"file": manifest_path.name, "error": str(e)},
                    "recommendation": "Review dataset manifest syntax."
                })

        for root, _, files in os.walk(dir_path):
            for file_name in files:
                fpath = Path(root) / file_name
                if fpath.name in (".gitkeep", ".DS_Store"):
                    continue

                files_inspected += 1
                f_size = fpath.stat().st_size
                total_bytes += f_size

                # 1. Compute SHA-256
                f_hash = self._compute_sha256(fpath)

                # 2. Check for unexpected script or executable
                ext = fpath.suffix.lower()
                is_exec_ext = ext in self.EXECUTABLE_EXTENSIONS
                is_magic_exec, magic_desc = self._check_executable_magic(fpath)

                if is_exec_ext or is_magic_exec:
                    findings.append({
                        "finding_id": f"f_ds_exec_{files_inspected:03d}",
                        "check": "dataset_guard",
                        "category": "dataset",
                        "severity": "high",
                        "confidence": "high",
                        "deterministic": True,
                        "title": f"Unexpected executable or script file in dataset: {fpath.name}",
                        "evidence": {
                            "file": fpath.relative_to(dir_path).as_posix(),
                            "extension": ext,
                            "magic_match": magic_desc if is_magic_exec else "File extension match",
                            "size_bytes": f_size,
                            "sha256": f_hash
                        },
                        "recommendation": (
                            "Inspect whether this script is expected pipeline tooling or untrusted code. "
                            "Datasets containing executable logic should be quarantined before training ingestion."
                        )
                    })

                # 3. Check manifest hash mismatch if manifest is present
                if manifest_data and "files" in manifest_data:
                    rel_path = fpath.relative_to(dir_path).as_posix()
                    if rel_path in manifest_data["files"]:
                        expected_hash = manifest_data["files"][rel_path].get("sha256")
                        if expected_hash and expected_hash.lower() != f_hash.lower():
                            findings.append({
                                "finding_id": f"f_ds_hash_mismatch_{files_inspected:03d}",
                                "check": "dataset_guard",
                                "category": "dataset",
                                "severity": "high",
                                "confidence": "high",
                                "deterministic": True,
                                "title": f"Hash integrity mismatch for dataset file: {rel_path}",
                                "evidence": {
                                    "file": rel_path,
                                    "expected_sha256": expected_hash,
                                    "actual_sha256": f_hash
                                },
                                "recommendation": "File content does not match publisher manifest. Reject or re-fetch."
                            })

                # 4. Basic schema validation for CSV/JSON/JSONL/Parquet
                if ext == ".csv":
                    self._check_csv_schema(fpath, dir_path, findings, files_inspected)
                elif ext == ".json":
                    self._check_json_schema(fpath, dir_path, findings, files_inspected)
                elif ext in (".jsonl", ".ndjson"):
                    self._check_jsonl_schema(fpath, dir_path, findings, files_inspected)
                elif ext == ".parquet":
                    self._check_parquet_integrity(fpath, dir_path, findings, files_inspected)

        # Informational finding if everything was clean
        if not findings:
            findings.append({
                "finding_id": "f_ds_clean",
                "check": "dataset_guard",
                "category": "dataset",
                "severity": "informational",
                "confidence": "high",
                "deterministic": True,
                "title": f"Dataset integrity verified across {files_inspected} files",
                "evidence": {
                    "files_count": files_inspected,
                    "total_bytes": total_bytes
                },
                "recommendation": "Dataset verified without unexpected executables or integrity failures."
            })
            status = "pass"
        else:
            has_crit_or_high = any(f.get("severity") in ("critical", "high") for f in findings)
            status = "fail" if has_crit_or_high else "warn"

        meta = {
            "name": dir_path.name,
            "files_count": files_inspected,
            "size_bytes": total_bytes,
            "detected_format": "dataset_directory"
        }
        return status, findings, meta

    def _compute_sha256(self, fpath: Path) -> str:
        hasher = hashlib.sha256()
        with open(fpath, "rb") as f:
            while chunk := f.read(65536):
                hasher.update(chunk)
        return hasher.hexdigest()

    def _check_executable_magic(self, fpath: Path) -> Tuple[bool, str]:
        try:
            with open(fpath, "rb") as f:
                prefix = f.read(16)
                for magic, desc in self.EXECUTABLE_MAGIC_PREFIXES:
                    if prefix.startswith(magic):
                        return True, desc
        except Exception:
            pass
        return False, ""

    def _check_csv_schema(self, fpath: Path, dir_path: Path, findings: list, idx: int):
        try:
            with open(fpath, "r", encoding="utf-8", errors="replace") as f:
                reader = csv.reader(f)
                header = next(reader, None)
                if not header:
                    findings.append({
                        "finding_id": f"f_ds_csv_empty_{idx}",
                        "check": "dataset_guard",
                        "category": "dataset",
                        "severity": "low",
                        "confidence": "high",
                        "deterministic": True,
                        "title": f"Empty CSV dataset: {fpath.name}",
                        "evidence": {"file": fpath.relative_to(dir_path).as_posix()},
                        "recommendation": "Check dataset content."
                    })
        except Exception as e:
            findings.append({
                "finding_id": f"f_ds_csv_err_{idx}",
                "check": "dataset_guard",
                "category": "dataset",
                "severity": "low",
                "confidence": "high",
                "deterministic": True,
                "title": f"CSV parse warning on {fpath.name}: {str(e)}",
                "evidence": {"error": str(e), "file": fpath.relative_to(dir_path).as_posix()},
                "recommendation": "Review CSV formatting."
            })

    def _check_json_schema(self, fpath: Path, dir_path: Path, findings: list, idx: int):
        try:
            with open(fpath, "r", encoding="utf-8", errors="replace") as f:
                json.load(f)
        except Exception as e:
            findings.append({
                "finding_id": f"f_ds_json_err_{idx}",
                "check": "dataset_guard",
                "category": "dataset",
                "severity": "low",
                "confidence": "high",
                "deterministic": True,
                "title": f"JSON parse warning on {fpath.name}: {str(e)}",
                "evidence": {"error": str(e), "file": fpath.relative_to(dir_path).as_posix()},
                "recommendation": "Ensure JSON formatting is valid."
            })

    def _check_jsonl_schema(self, fpath: Path, dir_path: Path, findings: list, idx: int):
        corrupted_lines = 0
        total_lines = 0
        try:
            with open(fpath, "r", encoding="utf-8", errors="replace") as f:
                for line in f:
                    total_lines += 1
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        json.loads(line)
                    except Exception:
                        corrupted_lines += 1
                        if corrupted_lines >= 5:
                            break
            if corrupted_lines > 0:
                findings.append({
                    "finding_id": f"f_ds_jsonl_err_{idx}",
                    "check": "dataset_guard",
                    "category": "dataset",
                    "severity": "medium",
                    "confidence": "high",
                    "deterministic": True,
                    "title": f"Malformed records detected in JSONL dataset: {fpath.name}",
                    "evidence": {
                        "file": fpath.relative_to(dir_path).as_posix(),
                        "corrupted_sample_count": corrupted_lines,
                        "lines_inspected": total_lines
                    },
                    "recommendation": "Dataset contains invalid JSON records that could fail training loaders."
                })
        except Exception as e:
            findings.append({
                "finding_id": f"f_ds_jsonl_read_err_{idx}",
                "check": "dataset_guard",
                "category": "dataset",
                "severity": "low",
                "confidence": "high",
                "deterministic": True,
                "title": f"Error reading JSONL dataset {fpath.name}: {str(e)}",
                "evidence": {"error": str(e), "file": fpath.relative_to(dir_path).as_posix()},
                "recommendation": "Review dataset encoding and permissions."
            })

    def _check_parquet_integrity(self, fpath: Path, dir_path: Path, findings: list, idx: int):
        """Verifies Parquet file starts and ends with standard PAR1 magic bytes."""
        try:
            f_size = fpath.stat().st_size
            if f_size < 12:
                findings.append({
                    "finding_id": f"f_ds_parquet_small_{idx}",
                    "check": "dataset_guard",
                    "category": "dataset",
                    "severity": "high",
                    "confidence": "high",
                    "deterministic": True,
                    "title": f"Truncated Parquet file: {fpath.name}",
                    "evidence": {"file": fpath.relative_to(dir_path).as_posix(), "size": f_size},
                    "recommendation": "Parquet files must be at least 12 bytes."
                })
                return

            with open(fpath, "rb") as f:
                header = f.read(4)
                f.seek(-4, os.SEEK_END)
                footer = f.read(4)

            if header != b"PAR1" or footer != b"PAR1":
                findings.append({
                    "finding_id": f"f_ds_parquet_corrupt_{idx}",
                    "check": "dataset_guard",
                    "category": "dataset",
                    "severity": "high",
                    "confidence": "high",
                    "deterministic": True,
                    "title": f"Spoofed or corrupted Parquet file: {fpath.name}",
                    "evidence": {
                        "file": fpath.relative_to(dir_path).as_posix(),
                        "header_magic": header.hex(),
                        "footer_magic": footer.hex()
                    },
                    "recommendation": "File with .parquet extension lacks PAR1 magic markers; potential extension spoofing."
                })
        except Exception as e:
            findings.append({
                "finding_id": f"f_ds_parquet_err_{idx}",
                "check": "dataset_guard",
                "category": "dataset",
                "severity": "medium",
                "confidence": "high",
                "deterministic": True,
                "title": f"Failed checking Parquet magic markers: {str(e)}",
                "evidence": {"error": str(e), "file": fpath.relative_to(dir_path).as_posix()},
                "recommendation": "Inspect file readability."
            })
