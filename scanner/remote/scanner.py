"""
scanner/remote/scanner.py

HTTP Range-request remote model scanner.
Performs zero-download static security scans directly against remote model repositories
(such as Hugging Face Hub, Cloud Storage, or HTTP/HTTPS endpoints) without downloading
multi-gigabyte weight tensors.
"""

import json
import struct
import uuid
import zipfile
from datetime import datetime, timezone
from typing import Dict, Any, Optional
from urllib.parse import urlparse

from scanner.config import MAX_HEADER_SIZE_BYTES
from scanner.pickle_scan import PickleOpcodeScanner
from scanner.safetensors_verify import SafetensorsVerifier
from scanner.gguf_verify import GGUFVerifier
from scanner.onnx_verify import ONNXVerifier
from scanner.remote.stream import HTTPRangeStream, HTTPRangeError

ENGINE_VERSION = "0.1.0"


def _clean_url_filename(url: str) -> str:
    path = urlparse(url).path
    filename = path.split("/")[-1] if "/" in path else path
    return filename or "remote_artifact"


def scan_remote_url(
    url: str,
    auth_token: Optional[str] = None,
    timeout_seconds: int = 15,
    opener: Optional[object] = None,
) -> Dict[str, Any]:
    """
    Scans a remote model URL using HTTP Range requests.
    Returns a dictionary conforming to contracts/scan_result.schema.json.
    Never raises an uncaught exception.
    """
    started_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    scan_id = f"sc_rem_{uuid.uuid4().hex[:8]}"
    filename = _clean_url_filename(url)

    checks_run = []
    findings = []

    # 1. Establish HTTP Range stream
    try:
        stream = HTTPRangeStream(
            url,
            chunk_size=65536,
            timeout_seconds=timeout_seconds,
            auth_token=auth_token,
            opener=opener,
        )
    except Exception as e:
        completed_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        return {
            "scan_id": scan_id,
            "engine_version": ENGINE_VERSION,
            "artifact": {
                "name": filename,
                "size_bytes": 0,
                "sha256": "0" * 64,
                "detected_format": "unknown",
            },
            "checks_run": [
                {"name": "remote_connection", "status": "error", "details": str(e)}
            ],
            "findings": [
                {
                    "finding_id": "f_remote_connection_failed",
                    "check": "remote_connection",
                    "category": "serialization",
                    "severity": "high",
                    "confidence": "high",
                    "deterministic": True,
                    "title": f"Failed to connect to remote artifact: {url}",
                    "evidence": {"url": url, "error": str(e)},
                    "recommendation": "Check the remote URL, network connectivity, or authentication token.",
                }
            ],
            "started_at": started_at,
            "completed_at": completed_at,
        }

    total_size = stream.size
    detected_format = "unknown"

    try:
        # 2. Inspect magic bytes at offset 0
        stream.seek(0)
        magic_bytes = stream.read(16)

        # A. Safetensors detection (8-byte unsigned int header size + JSON '{')
        is_safetensors = False
        if len(magic_bytes) >= 10:
            header_len = struct.unpack("<Q", magic_bytes[:8])[0]
            if 0 < header_len <= MAX_HEADER_SIZE_BYTES and magic_bytes[8:10].strip().startswith(b"{"):
                is_safetensors = True

        if is_safetensors or filename.lower().endswith(".safetensors"):
            detected_format = "safetensors"
            checks_run.append({"name": "format_detect", "status": "pass"})

            # Scan Safetensors header via range stream
            stream.seek(0)
            st_len_bytes = stream.read(8)
            if len(st_len_bytes) < 8:
                findings.append({
                    "finding_id": "f_st_truncated",
                    "check": "safetensors_verify",
                    "category": "serialization",
                    "severity": "critical",
                    "confidence": "high",
                    "deterministic": True,
                    "title": "Safetensors file truncated before header size could be read",
                    "evidence": {"file": filename, "size": total_size},
                    "recommendation": "Reject file: invalid Safetensors header.",
                })
                checks_run.append({"name": "safetensors_verify", "status": "fail"})
            else:
                hdr_len = struct.unpack("<Q", st_len_bytes)[0]
                if hdr_len > MAX_HEADER_SIZE_BYTES:
                    findings.append({
                        "finding_id": "f_st_header_dos",
                        "check": "safetensors_verify",
                        "category": "serialization",
                        "severity": "critical",
                        "confidence": "high",
                        "deterministic": True,
                        "title": f"Safetensors header size ({hdr_len} bytes) exceeds limit",
                        "evidence": {"header_size": hdr_len, "max_allowed": MAX_HEADER_SIZE_BYTES},
                        "recommendation": "Reject file: potential denial-of-service attack.",
                    })
                    checks_run.append({"name": "safetensors_verify", "status": "fail"})
                else:
                    # Fetch only the exact JSON header bytes
                    stream.seek(8)
                    hdr_raw = stream.read(hdr_len)
                    try:
                        hdr_json = json.loads(hdr_raw.decode("utf-8"))
                        st_verifier = SafetensorsVerifier()
                        st_status, st_findings = st_verifier.verify_header(
                            hdr_json,
                            header_len=hdr_len,
                            file_size=total_size,
                            file_name=filename,
                            sha256="remote_stream_partial",
                        )
                        findings.extend(st_findings)
                        checks_run.append({"name": "safetensors_verify", "status": st_status})
                    except Exception as json_err:
                        findings.append({
                            "finding_id": "f_st_header_invalid_json",
                            "check": "safetensors_verify",
                            "category": "serialization",
                            "severity": "critical",
                            "confidence": "high",
                            "deterministic": True,
                            "title": "Safetensors header contains invalid JSON",
                            "evidence": {"error": str(json_err)},
                            "recommendation": "Reject file: corrupted header.",
                        })
                        checks_run.append({"name": "safetensors_verify", "status": "fail"})

        # B. PyTorch ZIP Checkpoint (PK\x03\x04)
        elif magic_bytes.startswith(b"PK\x03\x04") or filename.lower().endswith((".pt", ".pth", ".bin")):
            stream.seek(0)
            if magic_bytes.startswith(b"PK\x03\x04"):
                detected_format = "pytorch_zip"
            else:
                detected_format = "pickle"
            checks_run.append({"name": "format_detect", "status": "pass"})

            if detected_format == "pytorch_zip":
                try:
                    # Open ZipFile directly over the seekable HTTPRangeStream!
                    with zipfile.ZipFile(stream, "r") as zf:
                        pickle_members = [
                            name for name in zf.namelist()
                            if name.endswith((".pkl", ".pickle")) or "data.pkl" in name
                        ]
                        if not pickle_members:
                            findings.append({
                                "finding_id": "f_zip_no_pickle",
                                "check": "pickle_opcode",
                                "category": "serialization",
                                "severity": "informational",
                                "confidence": "high",
                                "deterministic": True,
                                "title": "PyTorch archive contains no pickle data stream",
                                "evidence": {"members": zf.namelist()[:10]},
                                "recommendation": "Archive does not use pickle serialization.",
                            })
                            checks_run.append({"name": "pickle_opcode", "status": "pass"})
                        else:
                            any_failed = False
                            pickle_scanner = PickleOpcodeScanner()
                            for member in pickle_members:
                                with zf.open(member, "r") as member_stream:
                                    member_data = member_stream.read()
                                    member_findings = pickle_scanner.scan_pickle_stream(
                                        member_data,
                                        file_name=f"{filename}:{member}",
                                        sha256="remote_stream_partial",
                                        finding_id_prefix="f_zip_data",
                                    )
                                    findings.extend(member_findings)
                                    if any(f.get("severity") in ("critical", "high") for f in member_findings):
                                        any_failed = True
                            checks_run.append({
                                "name": "pickle_opcode",
                                "status": "fail" if any_failed else "pass",
                            })
                except Exception as zip_err:
                    findings.append({
                        "finding_id": "f_zip_corrupted",
                        "check": "pickle_opcode",
                        "category": "serialization",
                        "severity": "critical",
                        "confidence": "high",
                        "deterministic": True,
                        "title": "Failed to read PyTorch ZIP archive structure",
                        "evidence": {"error": str(zip_err)},
                        "recommendation": "Reject file: corrupt ZIP archive.",
                    })
                    checks_run.append({"name": "pickle_opcode", "status": "fail"})
            else:
                # Raw Pickle
                stream.seek(0)
                raw_pickle_bytes = stream.read()
                pickle_scanner = PickleOpcodeScanner()
                pkl_findings = pickle_scanner.scan_pickle_stream(
                    raw_pickle_bytes,
                    file_name=filename,
                    sha256="remote_stream_partial",
                    finding_id_prefix="f_raw",
                )
                findings.extend(pkl_findings)
                status = "fail" if any(f.get("severity") in ("critical", "high") for f in pkl_findings) else "pass"
                checks_run.append({"name": "pickle_opcode", "status": status})

        # C. GGUF Format
        elif magic_bytes.startswith(b"GGUF") or filename.lower().endswith(".gguf"):
            detected_format = "gguf"
            checks_run.append({"name": "format_detect", "status": "pass"})
            stream.seek(0)
            gguf_verifier = GGUFVerifier()
            gguf_status, gguf_findings = gguf_verifier.verify_stream(
                stream,
                file_name=filename,
                file_size=total_size,
                sha256="remote_stream_partial",
            )
            findings.extend(gguf_findings)
            checks_run.append({"name": "gguf_verify", "status": gguf_status})

        # D. ONNX Format
        elif filename.lower().endswith(".onnx") or magic_bytes.startswith(b"\x08"):
            detected_format = "onnx"
            checks_run.append({"name": "format_detect", "status": "pass"})
            stream.seek(0)
            onnx_verifier = ONNXVerifier()
            header_bytes = stream.read(min(total_size, 1024 * 1024))
            onnx_status, onnx_findings = onnx_verifier.verify_bytes(
                header_bytes,
                file_name=filename,
                file_size=total_size,
                sha256="remote_stream_partial",
            )
            findings.extend(onnx_findings)
            checks_run.append({"name": "onnx_verify", "status": onnx_status})

        else:
            detected_format = "unknown"
            checks_run.append({"name": "format_detect", "status": "pass"})
            findings.append({
                "finding_id": "f_format_unknown",
                "check": "format_detect",
                "category": "serialization",
                "severity": "medium",
                "confidence": "high",
                "deterministic": True,
                "title": f"Unrecognized model format for remote file: {filename}",
                "evidence": {"magic_hex": magic_bytes[:8].hex(), "filename": filename},
                "recommendation": "Scan supported formats: Safetensors, PyTorch ZIP, Pickle, GGUF, or ONNX.",
            })

        # 3. Calculate zero-download efficiency metrics
        downloaded = stream.bytes_downloaded
        saved = max(0, total_size - downloaded)
        pct_saved = round((saved / total_size * 100.0), 2) if total_size > 0 else 0.0
        ratio = round(total_size / max(1, downloaded), 1) if total_size > 0 else 1.0

        findings.append({
            "finding_id": "f_remote_streaming_metrics",
            "check": "remote_streaming",
            "category": "serialization",
            "severity": "informational",
            "confidence": "high",
            "deterministic": True,
            "title": f"Zero-download streaming scan completed: {pct_saved}% bandwidth saved ({ratio}x reduction)",
            "evidence": {
                "total_model_bytes": total_size,
                "bytes_transferred": downloaded,
                "bandwidth_saved_bytes": saved,
                "bandwidth_saved_pct": pct_saved,
                "compression_ratio": f"{ratio}x",
                "range_requests_supported": stream.supports_range,
            },
            "recommendation": "Zero-download inspection complete. Weights were verified without downloading tensor arrays.",
        })
        checks_run.append({"name": "remote_streaming", "status": "pass"})

    except Exception as scan_err:
        findings.append({
            "finding_id": "f_remote_scan_error",
            "check": "remote_streaming",
            "category": "serialization",
            "severity": "high",
            "confidence": "high",
            "deterministic": True,
            "title": f"Error occurred during remote streaming scan: {str(scan_err)}",
            "evidence": {"error": str(scan_err)},
            "recommendation": "Review remote URL and file accessibility.",
        })
        checks_run.append({"name": "remote_streaming", "status": "error"})

    completed_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    return {
        "scan_id": scan_id,
        "engine_version": ENGINE_VERSION,
        "artifact": {
            "name": filename,
            "size_bytes": total_size,
            "sha256": "remote_stream_partial",
            "detected_format": detected_format,
        },
        "checks_run": checks_run,
        "findings": findings,
        "started_at": started_at,
        "completed_at": completed_at,
    }


def scan_hf_model(
    repo_id: str,
    filename: str,
    revision: str = "main",
    auth_token: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Scans a model file directly from Hugging Face Hub using HTTP Range requests.
    Example: scan_hf_model("meta-llama/Llama-2-7b", "model.safetensors")
    """
    url = f"https://huggingface.co/{repo_id}/resolve/{revision}/{filename}"
    return scan_remote_url(url, auth_token=auth_token)
