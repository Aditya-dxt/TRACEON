"""Database model tests using an isolated SQLite database."""

import pytest
from sqlalchemy import create_engine, event, inspect
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from app.db.base import Base
from app.db.models import Asset, Decision, FindingRecord, Scan


@pytest.fixture
def database_engine():
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )

    @event.listens_for(engine, "connect")
    def enable_foreign_keys(connection, connection_record):
        cursor = connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()

    Base.metadata.create_all(engine)
    yield engine
    engine.dispose()


def test_schema_has_all_backend_record_tables(database_engine):
    tables = set(inspect(database_engine).get_table_names())
    assert {
        "assets",
        "scans",
        "findings",
        "decisions",
        "attestations",
        "audit_log",
    }.issubset(tables)


def test_scanner_result_and_utc_timestamps_round_trip(database_engine):
    scanner_result = {
        "scan_id": "sc_001",
        "engine_version": "0.1.0",
        "artifact": {"name": "model.safetensors", "size_bytes": 12},
        "checks_run": [{"name": "format_detect", "status": "pass"}],
        "findings": [],
        "started_at": "2026-11-19T10:00:00Z",
        "completed_at": "2026-11-19T10:00:01Z",
    }
    with Session(database_engine) as session:
        asset = Asset(
            asset_id="a_001",
            name="model.safetensors",
            source="huggingface:example/model@main",
            file_format="safetensors",
            size_bytes=12,
            sha256="a" * 64,
        )
        scan = Scan(
            scan_id="sc_001",
            asset=asset,
            status="completed",
            engine_version="0.1.0",
            result_json=scanner_result,
        )
        finding = FindingRecord(
            scan=scan,
            finding_id="f_001",
            check="pickle_opcode",
            category="serialization",
            severity="critical",
            confidence="high",
            deterministic=True,
            title="Deny-listed import in pickle",
            evidence={"module": "posix", "callable": "system"},
            recommendation="Do not load this file.",
        )
        session.add_all([asset, scan, finding])
        session.commit()

        loaded_scan = session.get(Scan, "sc_001")
        assert loaded_scan is not None
        assert loaded_scan.result_json == scanner_result
        assert loaded_scan.queued_at.tzinfo is not None
        assert loaded_scan.queued_at.utcoffset().total_seconds() == 0
        assert loaded_scan.findings[0].finding_id == "f_001"


def test_decision_cannot_link_a_scan_to_another_asset(database_engine):
    with Session(database_engine) as session:
        first_asset = Asset(
            asset_id="a_001",
            name="one.bin",
            source="upload",
            file_format="pickle",
            size_bytes=1,
            sha256="1" * 64,
        )
        second_asset = Asset(
            asset_id="a_002",
            name="two.bin",
            source="upload",
            file_format="pickle",
            size_bytes=1,
            sha256="2" * 64,
        )
        scan = Scan(scan_id="sc_001", asset=first_asset, status="queued")
        session.add_all([first_asset, second_asset, scan])
        session.commit()

        session.add(
            Decision(
                decision_id="d_001",
                asset_id="a_002",
                scan_id="sc_001",
                verdict="APPROVE",
                reasons=[],
                policy_id="default",
                policy_version=1,
            )
        )
        with pytest.raises(IntegrityError):
            session.commit()
