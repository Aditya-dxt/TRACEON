"""
scanner/tests/test_remote.py

Unit tests for HTTP Range-request zero-download model scanner.
Uses a mock in-memory HTTP Range transport for fast, deterministic, sandboxed execution.
"""

import io
import urllib.error
import urllib.request
from pathlib import Path
import pytest

from scanner import scan_remote_url, scan_hf_model

CORPUS_DIR = Path(__file__).resolve().parent.parent / "corpus"


class MockHTTPResponse:
    """Mock HTTP response object mimicking http.client.HTTPResponse."""

    def __init__(self, data: bytes, status: int, headers: dict):
        self._data = data
        self.status = status
        self.headers = headers

    def read(self, size: int = -1) -> bytes:
        if size == -1:
            return self._data
        return self._data[:size]

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        pass


def make_corpus_opener():
    """Returns a mock URL opener serving local test corpus files via HTTP Range protocol."""

    def _opener(req: urllib.request.Request, timeout: int = 15):
        url = req.full_url
        filename = url.split("/")[-1]
        file_path = CORPUS_DIR / filename

        if not file_path.exists():
            raise urllib.error.HTTPError(url, 404, "Not Found", {}, None)

        total_bytes = file_path.read_bytes()
        total_size = len(total_bytes)

        # 1. HEAD request
        if getattr(req, "get_method", lambda: "GET")() == "HEAD":
            return MockHTTPResponse(
                b"",
                200,
                {
                    "content-length": str(total_size),
                    "accept-ranges": "bytes",
                    "content-type": "application/octet-stream",
                },
            )

        # 2. GET request with Range
        range_hdr = None
        for k, v in req.headers.items():
            if k.lower() == "range":
                range_hdr = v
                break

        if range_hdr and range_hdr.startswith("bytes="):
            rng = range_hdr.replace("bytes=", "").strip()
            parts = rng.split("-")
            start = int(parts[0]) if parts[0] else 0
            end = int(parts[1]) if parts[1] else total_size - 1
            end = min(end, total_size - 1)
            chunk = total_bytes[start : end + 1]
            return MockHTTPResponse(
                chunk,
                206,
                {
                    "content-range": f"bytes {start}-{end}/{total_size}",
                    "content-length": str(len(chunk)),
                    "accept-ranges": "bytes",
                },
            )

        # 3. GET request without Range
        return MockHTTPResponse(
            total_bytes,
            200,
            {
                "content-length": str(total_size),
                "accept-ranges": "bytes",
            },
        )

    return _opener


@pytest.fixture
def corpus_opener():
    return make_corpus_opener()


def test_remote_scan_safetensors_clean(corpus_opener):
    url = "https://huggingface.co/example-org/model/resolve/main/valid.safetensors"
    result = scan_remote_url(url, opener=corpus_opener)

    assert result["artifact"]["detected_format"] == "safetensors"
    check_names = [c["name"] for c in result["checks_run"]]
    assert "format_detect" in check_names
    assert "safetensors_verify" in check_names
    assert "remote_streaming" in check_names

    # Check zero-download bandwidth savings
    metrics = next(f for f in result["findings"] if f["finding_id"] == "f_remote_streaming_metrics")
    assert metrics["severity"] == "informational"
    assert metrics["evidence"]["range_requests_supported"] is True
    assert "bytes_transferred" in metrics["evidence"]


def test_remote_scan_safetensors_malformed_past_eof(corpus_opener):
    url = "https://huggingface.co/example-org/model/resolve/main/malformed.safetensors"
    result = scan_remote_url(url, opener=corpus_opener)

    assert result["artifact"]["detected_format"] == "safetensors"
    f_ids = [f["finding_id"] for f in result["findings"]]
    assert any("offset_past_eof" in fid for fid in f_ids)
    st_check = next(c for c in result["checks_run"] if c["name"] == "safetensors_verify")
    assert st_check["status"] == "fail"


def test_remote_scan_pytorch_zip_evil(corpus_opener):
    url = "https://huggingface.co/example-org/model/resolve/main/pytorch_evil.pt"
    result = scan_remote_url(url, opener=corpus_opener)

    assert result["artifact"]["detected_format"] == "pytorch_zip"
    f_ids = [f["finding_id"] for f in result["findings"]]
    assert "f_zip_data_001" in f_ids

    evil_finding = next(f for f in result["findings"] if f["finding_id"] == "f_zip_data_001")
    assert evil_finding["severity"] == "critical"
    assert evil_finding["evidence"]["module"] == "posix"
    assert evil_finding["evidence"]["callable"] == "system"


def test_remote_scan_raw_pickle_evil(corpus_opener):
    url = "https://huggingface.co/example-org/model/resolve/main/evil.bin"
    result = scan_remote_url(url, opener=corpus_opener)

    assert result["artifact"]["detected_format"] == "pickle"
    f_ids = [f["finding_id"] for f in result["findings"]]
    assert "f_raw_001" in f_ids

    raw_finding = next(f for f in result["findings"] if f["finding_id"] == "f_raw_001")
    assert raw_finding["severity"] == "critical"
    assert raw_finding["evidence"]["callable"] == "system"


def test_remote_scan_connection_failure_non_raising():
    # Use invalid host where connection will fail gracefully
    bad_url = "http://127.0.0.1:59999/nonexistent.safetensors"
    result = scan_remote_url(bad_url, timeout_seconds=1)

    assert result["artifact"]["detected_format"] == "unknown"
    assert result["checks_run"][0]["status"] == "error"
    assert result["findings"][0]["finding_id"] == "f_remote_connection_failed"
    assert result["findings"][0]["severity"] == "high"


def test_hf_url_construction():
    # Verify Hugging Face model URL resolution
    res = scan_hf_model("test-org/dummy-repo", "weights.safetensors")
    assert res["artifact"]["name"] == "weights.safetensors"
    assert isinstance(res["findings"], list)
