"""
scanner/format_detect.py

Robust file format detection and streaming SHA-256 computation.
Never executes or loads any untrusted file.
"""

import os
import json
import struct
import hashlib
import zipfile
from pathlib import Path
from typing import Tuple, Dict, Any, List


def compute_sha256_and_size(file_path: Path, chunk_size: int = 65536) -> Tuple[str, int]:
    """Streams a file to compute its SHA-256 hash and size without loading into memory."""
    hasher = hashlib.sha256()
    total_size = 0
    with open(file_path, "rb") as f:
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break
            hasher.update(chunk)
            total_size += len(chunk)
    return hasher.hexdigest(), total_size


def detect_format(file_path: Path) -> Tuple[str, Dict[str, Any]]:
    """
    Detects the file format using magic bytes, headers, and archive inspection.
    Returns:
        (detected_format_str, metadata_dict)
    """
    if not file_path.is_file():
        return "unknown", {"error": "Path is not a regular file"}

    file_size = file_path.stat().st_size
    if file_size == 0:
        return "empty", {"error": "File is empty"}

    # Read first 1024 bytes for inspection
    with open(file_path, "rb") as f:
        header = f.read(min(1024, file_size))

    # 1. Check GGUF (Magic: b'GGUF')
    if header.startswith(b"GGUF"):
        return "gguf", {"magic": "GGUF"}

    # 2. Check NumPy (Magic: b'\x93NUMPY')
    if header.startswith(b"\x93NUMPY"):
        return "numpy", {"magic": "NUMPY"}

    # 3. Check Parquet (Magic: b'PAR1')
    if header.startswith(b"PAR1"):
        return "parquet", {"magic": "PAR1"}

    # 4. Check Safetensors:
    # 8-byte uint64 LE header size, followed by JSON starting with '{'
    if file_size >= 10:
        header_len = struct.unpack("<Q", header[:8])[0]
        if 2 <= header_len < 100 * 1024 * 1024 and (8 + header_len) <= file_size:
            # Check if next byte is '{'
            if len(header) > 8 and header[8:9] == b"{":
                return "safetensors", {"header_len": header_len}

    # 5. Check ZIP / PyTorch Zip Archive (Magic: PK\x03\x04)
    if header.startswith(b"PK\x03\x04"):
        try:
            with zipfile.ZipFile(file_path, "r") as zf:
                namelist = zf.namelist()
                has_pickle = any(name.endswith(".pkl") or "data.pkl" in name for name in namelist)
                is_pytorch = any("pytorch" in name.lower() or name.startswith("archive/") or "byteorder" in name for name in namelist)
                return "pytorch_zip" if (has_pickle or is_pytorch) else "zip", {
                    "entries_count": len(namelist),
                    "contains_pickle": has_pickle,
                    "sample_entries": namelist[:5]
                }
        except zipfile.BadZipFile:
            return "corrupted_zip", {"error": "Invalid zip file structure"}

    # 6. Check Pickle Protocols
    # Protocol 2..5: \x80\x02, \x80\x03, \x80\x04, \x80\x05
    if header.startswith(b"\x80") and len(header) >= 2 and header[1] in (1, 2, 3, 4, 5):
        return "pickle", {"protocol": header[1]}

    # Protocol 0 text pickle or GLOBAL opcode 'c' at start
    if header.startswith(b"c") or header.startswith(b"(dp") or header.startswith(b"(lp"):
        return "pickle", {"protocol": 0}

    # 7. Check JSON
    stripped_header = header.strip()
    if stripped_header.startswith(b"{") or stripped_header.startswith(b"["):
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                json.load(f)
            return "json", {}
        except Exception:
            pass

    # 8. Check ONNX (Protobuf - typically starts with field tag \x08 for ir_version)
    if header.startswith(b"\x08") and file_path.suffix.lower() == ".onnx":
        return "onnx", {}

    return "unknown", {"extension": file_path.suffix}
