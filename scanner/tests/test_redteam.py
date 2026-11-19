"""
scanner/tests/test_redteam.py

Aditya Dixit's Red-Team and Evasion Test Suite for Traceon Scanner.
Tests evasions, malformed headers, recursion depth, and parser resilience.
All tests use harmless, synthetic fixtures.
"""

import io
import json
import struct
import zipfile
import pytest
from pathlib import Path

from scanner import scan_artifact, scan_dataset
from scanner.config import MAX_HEADER_SIZE_BYTES


def test_redteam_truncated_safetensors_header(tmp_path):
    """File claims header is 5000 bytes, but ends after 20 bytes."""
    bad_file = tmp_path / "truncated_header.safetensors"
    with open(bad_file, "wb") as f:
        f.write(struct.pack("<Q", 5000))
        f.write(b'{"weight": {"dtype":')  # truncated JSON

    result = scan_artifact(str(bad_file))
    check_statuses = {c["name"]: c["status"] for c in result["checks_run"]}
    assert check_statuses.get("safetensors_verify") == "fail"
    crit_findings = [f for f in result["findings"] if f["severity"] == "critical"]
    assert len(crit_findings) >= 1


def test_redteam_header_dos_attack(tmp_path):
    """File claims header is 10 GB to exhaust scanner memory."""
    dos_file = tmp_path / "gigantic_header.safetensors"
    with open(dos_file, "wb") as f:
        # Declare 10GB header length
        f.write(struct.pack("<Q", 10 * 1024 * 1024 * 1024))
        f.write(b"dummy")

    result = scan_artifact(str(dos_file))
    check_statuses = {c["name"]: c["status"] for c in result["checks_run"]}
    assert check_statuses.get("safetensors_verify") == "fail"


def test_redteam_truncated_pickle_stream(tmp_path):
    """Corrupted / truncated pickle stream cuts off abruptly."""
    bad_pkl = tmp_path / "truncated.pkl"
    # Protocol 2 pickle cut off right after GLOBAL opcode
    bad_pkl.write_bytes(b"\x80\x02cposix\nsys")

    result = scan_artifact(str(bad_pkl))
    # Must never raise an uncaught exception
    assert result["artifact"]["name"] == "truncated.pkl"


def test_redteam_zip_slip_resilience(tmp_path):
    """Zip archive containing path traversal entries like ../../sensitive.txt"""
    zip_slip_file = tmp_path / "traversal.pt"
    with zipfile.ZipFile(zip_slip_file, "w") as zf:
        zf.writestr("../../escape_marker.txt", "harmless marker test")
        # Add benign pickle
        zf.writestr("archive/data.pkl", b"\x80\x04}\x94.")

    result = scan_artifact(str(zip_slip_file))
    assert result["artifact"]["detected_format"] == "pytorch_zip"
    # Scanner parses purely in-memory; no files are extracted to host disk
    assert not (tmp_path.parent / "escape_marker.txt").exists()


def test_redteam_stack_global_obfuscation(tmp_path):
    """Protocol 4 STACK_GLOBAL opcode importing builtins.eval."""
    # Bytecode:
    # \x80\x04 : PROTO 4
    # \x8c\x08builtins : SHORT_BINUNICODE 'builtins'
    # \x8c\x04eval : SHORT_BINUNICODE 'eval'
    # \x93 : STACK_GLOBAL
    # . : STOP
    payload = b"\x80\x04\x8c\x08builtins\x8c\x04eval\x93."
    stack_file = tmp_path / "stack_global.pkl"
    stack_file.write_bytes(payload)

    result = scan_artifact(str(stack_file))
    check_statuses = {c["name"]: c["status"] for c in result["checks_run"]}
    assert check_statuses.get("pickle_opcode") == "fail"
    crit_findings = [f for f in result["findings"] if f["severity"] == "critical"]
    assert len(crit_findings) >= 1
    assert "eval" in crit_findings[0]["title"] or "builtins" in crit_findings[0]["title"]


def test_redteam_zero_byte_files(tmp_path):
    """Zero-byte files must not crash any parser."""
    empty_file = tmp_path / "empty_model.safetensors"
    empty_file.write_bytes(b"")

    result = scan_artifact(str(empty_file))
    assert result["artifact"]["size_bytes"] == 0
    assert result["artifact"]["detected_format"] == "empty"
