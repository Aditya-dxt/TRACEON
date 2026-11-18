"""
scanner/pickle_scan/scanner.py

Safe static pickle opcode scanner.
Strictly disassembles using pickletools.genops.
NEVER loads or executes pickle files.
"""

import io
import pickletools
import zipfile
from pathlib import Path
from typing import List, Dict, Any, Tuple

from scanner.config import (
    DENY_LISTED_MODULES,
    DENY_LISTED_CALLABLES,
    SAFE_ALLOWED_GLOBALS,
    MAX_PICKLE_NESTING_DEPTH
)


class PickleOpcodeScanner:
    def __init__(self):
        self.deny_modules = DENY_LISTED_MODULES
        self.deny_callables = DENY_LISTED_CALLABLES
        self.safe_globals = SAFE_ALLOWED_GLOBALS

    def scan_pickle_stream(
        self,
        stream_data: bytes,
        file_name: str,
        sha256: str,
        finding_id_prefix: str = "f_pickle"
    ) -> List[Dict[str, Any]]:
        """
        Disassembles raw pickle stream bytes using pickletools.genops.
        Never executes any code.
        """
        findings = []
        finding_counter = 1

        try:
            # pickletools.genops yields (opcode, arg, pos)
            # opcode.name can be 'GLOBAL', 'STACK_GLOBAL', 'REDUCE', 'BUILD', etc.
            # In pickle bytecode, GLOBAL arg is 'module name\ncallable name'
            stack = []

            for opcode, arg, pos in pickletools.genops(stream_data):
                hex_offset = f"0x{pos:04X}"

                # Handle standard GLOBAL opcode
                if opcode.name == "GLOBAL":
                    if isinstance(arg, str):
                        parts = arg.strip().split()
                        if len(parts) >= 2:
                            module, callable_name = parts[0], parts[1]
                        elif len(parts) == 1:
                            module, callable_name = parts[0], ""
                        else:
                            module, callable_name = "unknown", "unknown"
                    else:
                        module, callable_name = "unknown", "unknown"

                    finding = self._evaluate_global(
                        module, callable_name, hex_offset, file_name, sha256,
                        f"{finding_id_prefix}_{finding_counter:03d}"
                    )
                    if finding:
                        findings.append(finding)
                        finding_counter += 1

                # Handle STACK_GLOBAL opcode (Protocol 4+)
                elif opcode.name == "STACK_GLOBAL":
                    # STACK_GLOBAL pulls module and name from stack
                    # Because we don't execute, we track recent string pushes on stack
                    module = stack.pop() if stack else "unknown_stack_module"
                    callable_name = stack.pop() if stack else "unknown_stack_callable"
                    if isinstance(module, str) and isinstance(callable_name, str):
                        # Clean string representations
                        module = module.strip("'\"")
                        callable_name = callable_name.strip("'\"")
                        finding = self._evaluate_global(
                            module, callable_name, hex_offset, file_name, sha256,
                            f"{finding_id_prefix}_{finding_counter:03d}"
                        )
                        if finding:
                            findings.append(finding)
                            finding_counter += 1

                # Track string literals pushed onto stack for STACK_GLOBAL
                elif opcode.name in ("SHORT_BINUNICODE", "BINUNICODE", "UNICODE", "BINSTRING", "SHORT_BINSTRING"):
                    if isinstance(arg, str):
                        stack.append(arg)
                        if len(stack) > 50:
                            stack.pop(0)

        except Exception as e:
            # If disassembly fails (malformed pickle), emit an informational or medium finding
            findings.append({
                "finding_id": f"{finding_id_prefix}_err",
                "check": "pickle_opcode",
                "category": "serialization",
                "severity": "medium",
                "confidence": "high",
                "deterministic": True,
                "title": f"Malformed or truncated pickle stream: {str(e)}",
                "evidence": {
                    "file": file_name,
                    "sha256": sha256,
                    "error": str(e)
                },
                "recommendation": "Do not load unparseable pickle streams."
            })

        return findings

    def _evaluate_global(
        self,
        module: str,
        callable_name: str,
        offset: str,
        file_name: str,
        sha256: str,
        finding_id: str
    ) -> Dict[str, Any] | None:
        # Check against Deny-List
        is_module_denied = module in self.deny_modules or any(module.startswith(m + ".") for m in self.deny_modules)
        is_callable_denied = callable_name in self.deny_callables

        if is_module_denied or is_callable_denied:
            return {
                "finding_id": finding_id,
                "check": "pickle_opcode",
                "category": "serialization",
                "severity": "critical",
                "confidence": "high",
                "deterministic": True,
                "title": f"Deny-listed import in pickle: {module}.{callable_name}",
                "evidence": {
                    "module": module,
                    "callable": callable_name,
                    "offset": offset,
                    "file": file_name,
                    "sha256": sha256
                },
                "recommendation": "Do not load this file. Request a Safetensors version."
            }

        # Check against Safe Allow-List
        if (module, callable_name) in self.safe_globals:
            return None

        # If not explicitly allow-listed and not standard builtins safe types:
        if module not in ("torch", "torch._utils", "numpy", "collections"):
            return {
                "finding_id": finding_id,
                "check": "pickle_opcode",
                "category": "serialization",
                "severity": "high",
                "confidence": "medium",
                "deterministic": True,
                "title": f"Unapproved global import in pickle: {module}.{callable_name}",
                "evidence": {
                    "module": module,
                    "callable": callable_name,
                    "offset": offset,
                    "file": file_name,
                    "sha256": sha256
                },
                "recommendation": "Verify why this checkpoint imports arbitrary classes or modules."
            }

        return None

    def scan_file(self, file_path: Path, sha256: str) -> Tuple[str, List[Dict[str, Any]]]:
        """
        Scans a file for pickle opcodes.
        Handles both raw pickle files and PyTorch ZIP archives containing data.pkl.
        Returns: (status: 'pass' | 'fail', findings: list)
        """
        findings = []

        # Check if file is a zip archive (e.g. PyTorch checkpoint)
        if zipfile.is_zipfile(file_path):
            try:
                with zipfile.ZipFile(file_path, "r") as zf:
                    for member_name in zf.namelist():
                        if member_name.endswith(".pkl") or "data.pkl" in member_name or member_name.endswith("/data"):
                            with zf.open(member_name) as mf:
                                pkl_data = mf.read()
                                member_findings = self.scan_pickle_stream(
                                    pkl_data,
                                    file_name=f"{file_path.name}:{member_name}",
                                    sha256=sha256,
                                    finding_id_prefix=f"f_zip_{Path(member_name).stem}"
                                )
                                findings.extend(member_findings)
            except Exception as e:
                findings.append({
                    "finding_id": "f_zip_read_err",
                    "check": "pickle_opcode",
                    "category": "serialization",
                    "severity": "medium",
                    "confidence": "high",
                    "deterministic": True,
                    "title": f"Failed reading zip archive: {str(e)}",
                    "evidence": {"file": file_path.name, "sha256": sha256},
                    "recommendation": "Inspect archive integrity."
                })
        else:
            # Raw pickle file
            try:
                with open(file_path, "rb") as f:
                    data = f.read()
                raw_findings = self.scan_pickle_stream(
                    data,
                    file_name=file_path.name,
                    sha256=sha256,
                    finding_id_prefix="f_raw"
                )
                findings.extend(raw_findings)
            except Exception as e:
                findings.append({
                    "finding_id": "f_read_err",
                    "check": "pickle_opcode",
                    "category": "serialization",
                    "severity": "medium",
                    "confidence": "high",
                    "deterministic": True,
                    "title": f"Error reading file: {str(e)}",
                    "evidence": {"file": file_path.name, "sha256": sha256},
                    "recommendation": "Check file permissions and integrity."
                })

        has_critical_or_high = any(f.get("severity") in ("critical", "high") for f in findings)
        status = "fail" if has_critical_or_high else "pass"
        return status, findings
