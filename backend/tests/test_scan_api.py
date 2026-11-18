"""Scanner runner and scan route integration tests without a network listener."""

import hashlib
import json
from pathlib import Path

import pytest
from fastapi import BackgroundTasks, HTTPException
from sqlalchemy import create_engine, event, select
from sqlalchemy.orm import sessionmaker

from app.db.base import Base
from app.db.models import Asset, FindingRecord, Scan
from app.main import app, create_scan, get_scan
from app.models import StartScanRequest
from app.services import scan_runner


@pytest.fixture
def test_database(monkeypatch, tmp_path):
    engine = create_engine(
        f"sqlite:///{tmp_path / 'scan-api.db'}",
        connect_args={"check_same_thread": False},
    )

    @event.listens_for(engine, "connect")
    def enable_foreign_keys(connection, connection_record):
        cursor = connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()

    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)
    monkeypatch.setattr(scan_runner, "SessionLocal", factory)
    yield factory
    engine.dispose()


def complete_sync_coroutine(coroutine):
    """Run a route coroutine that contains no awaits without opening an event loop."""

    with pytest.raises(StopIteration) as completed:
        coroutine.send(None)
    return completed.value.value


def test_post_and_get_scan_store_scanner_result_unchanged(
    test_database, tmp_path, monkeypatch
):
    artifact = tmp_path / "model.bin"
    artifact.write_bytes(b"synthetic")
    scanner_result = {
        "scan_id": "sc_scanner001",
        "engine_version": "0.1.0",
        "artifact": {
            "name": "model.bin",
            "size_bytes": 9,
            "sha256": "a" * 64,
            "detected_format": "unknown",
        },
        "checks_run": [{"name": "format_detect", "status": "pass"}],
        "findings": [
            {
                "finding_id": "f_001",
                "check": "pickle_opcode",
                "category": "serialization",
                "severity": "critical",
                "confidence": "high",
                "deterministic": True,
                "title": "Synthetic finding",
                "evidence": {"sha256": "a" * 64},
                "recommendation": "Do not load this file.",
            }
        ],
        "started_at": "2026-11-19T10:00:00Z",
        "completed_at": "2026-11-19T10:00:01Z",
    }

    with test_database() as session:
        session.add(
            Asset(
                asset_id="a_001",
                name="model.bin",
                source="upload",
                file_format="unknown",
                size_bytes=9,
                sha256="a" * 64,
                storage_path=str(artifact),
            )
        )
        session.commit()

        background_tasks = BackgroundTasks()
        queued = complete_sync_coroutine(
            create_scan(
                StartScanRequest(asset_id="a_001"),
                background_tasks,
                session,
            )
        )
        queued_data = queued.model_dump(mode="json")
        assert queued_data["asset_id"] == "a_001"
        assert queued_data["status"] == "queued"
        assert len(background_tasks.tasks) == 1

    def fake_scan(path):
        assert path == str(artifact)
        return scanner_result

    monkeypatch.setattr(scan_runner, "scan_artifact", fake_scan)
    task = background_tasks.tasks[0]
    task.func(*task.args, **task.kwargs)

    with test_database() as session:
        stored = session.get(Scan, queued_data["scan_id"])
        assert stored is not None
        assert stored.result_json == scanner_result
        assert stored.scanner_scan_id == "sc_scanner001"
        assert stored.status == "completed"
        findings = session.scalars(
            select(FindingRecord).where(FindingRecord.scan_id == queued_data["scan_id"])
        ).all()
        assert len(findings) == 1
        assert findings[0].finding_id == "f_001"

        response = complete_sync_coroutine(get_scan(queued_data["scan_id"], session))
        assert response.status_code == 200
        assert json.loads(response.body) == scanner_result


def test_scan_api_returns_standard_error_for_missing_assets(test_database):
    with test_database() as session:
        with pytest.raises(HTTPException) as raised:
            complete_sync_coroutine(
                create_scan(
                    StartScanRequest(asset_id="missing"),
                    BackgroundTasks(),
                    session,
                )
            )
    assert raised.value.status_code == 404
    assert raised.value.detail == {
        "error": "Asset not found",
        "code": "ASSET_NOT_FOUND",
    }


def test_runner_calls_the_scanner_package_on_a_synthetic_clean_artifact(test_database):
    artifact = Path(__file__).resolve().parents[2] / "scanner" / "corpus" / "clean.pkl"
    digest = hashlib.sha256(artifact.read_bytes()).hexdigest()
    with test_database() as session:
        session.add(
            Asset(
                asset_id="a_clean",
                name=artifact.name,
                source="synthetic-test-corpus",
                file_format="pickle",
                size_bytes=artifact.stat().st_size,
                sha256=digest,
                storage_path=str(artifact),
            )
        )
        session.add(Scan(scan_id="sc_request01", asset_id="a_clean", status="queued"))
        session.commit()

    scan_runner.run_scan("sc_request01")

    with test_database() as session:
        stored = session.get(Scan, "sc_request01")
        assert stored is not None
        assert stored.status == "completed"
        assert stored.result_json is not None
        assert stored.result_json["artifact"]["sha256"] == digest
        assert stored.scanner_scan_id == stored.result_json["scan_id"]
        assert "verdict" not in stored.result_json


def test_scan_routes_are_registered():
    routes = {(route.path, method) for route in app.routes for method in route.methods or []}
    assert ("/v1/scans", "POST") in routes
    assert ("/v1/scans/{scan_id}", "GET") in routes
