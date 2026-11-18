"""Unit tests for quarantine retrieval and sandbox command construction."""

import json
from types import SimpleNamespace

import pytest
from fastapi import HTTPException

import infra.sandbox.app as worker


class FakeBlob:
    size = 9

    def __init__(self):
        self.downloaded_to = None

    def reload(self):
        return None

    def download_to_filename(self, path):
        self.downloaded_to = path
        with open(path, "wb") as stream:
            stream.write(b"synthetic")


class FakeBucket:
    def __init__(self, blob):
        self._blob = blob
        self.requested_name = None
        self.requested_generation = None

    def blob(self, name, generation=None):
        self.requested_name = name
        self.requested_generation = generation
        return self._blob


class FakeStorageClient:
    def __init__(self, bucket):
        self._bucket = bucket

    def bucket(self, name):
        assert name == "traceon-quarantine-test"
        return self._bucket


def test_worker_downloads_only_from_configured_bucket_then_calls_sandbox(
    tmp_path, monkeypatch
):
    blob = FakeBlob()
    bucket = FakeBucket(blob)
    monkeypatch.setattr(worker, "QUARANTINE_BUCKET", "traceon-quarantine-test")
    monkeypatch.setattr(worker.storage, "Client", lambda: FakeStorageClient(bucket))
    seen = {}

    def sandbox_scan(path):
        seen["path"] = path
        assert path.read_bytes() == b"synthetic"
        return {"scan_id": "sc_001", "findings": []}

    monkeypatch.setattr(worker, "_sandbox_scan", sandbox_scan)
    result = worker.scan_object(worker.ScanRequest(object_name="asset/a_001", generation=7))

    assert result == {"scan_id": "sc_001", "findings": []}
    assert bucket.requested_name == "asset/a_001"
    assert bucket.requested_generation == 7
    assert not seen["path"].exists()


def test_worker_rejects_oversized_objects_before_download(monkeypatch):
    blob = FakeBlob()
    blob.size = worker.MAX_ARTIFACT_BYTES + 1
    bucket = FakeBucket(blob)
    monkeypatch.setattr(worker, "QUARANTINE_BUCKET", "traceon-quarantine-test")
    monkeypatch.setattr(worker.storage, "Client", lambda: FakeStorageClient(bucket))
    with pytest.raises(HTTPException) as raised:
        worker._download_quarantined_object(
            worker.ScanRequest(object_name="asset/a_001"),
            worker.Path("unused"),
        )
    assert raised.value.status_code == 413
    assert blob.downloaded_to is None


def test_sandbox_command_keeps_default_no_egress_policy(tmp_path, monkeypatch):
    cli = tmp_path / "sandbox"
    cli.write_text("", encoding="utf-8")
    monkeypatch.setattr(worker, "SANDBOX_CLI", str(cli))
    captured = {}

    def fake_run(command, **kwargs):
        captured["command"] = command
        captured["kwargs"] = kwargs
        return SimpleNamespace(returncode=0, stdout=json.dumps({"scan_id": "sc_001"}))

    monkeypatch.setattr(worker.subprocess, "run", fake_run)
    result = worker._sandbox_scan(tmp_path / "artifact")

    assert result == {"scan_id": "sc_001"}
    assert "--allow-egress" not in captured["command"]
    assert captured["command"][1:3] == ["do", "--"]
    assert captured["kwargs"]["timeout"] == worker.SCAN_TIMEOUT_SECONDS
