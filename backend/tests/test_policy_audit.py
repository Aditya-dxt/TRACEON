import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.db.base import Base
from app.db.models import Asset, AuditLogEntry, Scan
from app.services.audit import append_audit_event, verify_audit_chain
from app.services.policy import evaluate_scan


@pytest.fixture
def test_database(tmp_path):
    engine = create_engine(f"sqlite:///{tmp_path / 'audit.db'}")
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)
    yield factory
    engine.dispose()


def test_policy_uses_documented_deterministic_precedence():
    asset = Asset(asset_id="a", name="m", source="test", file_format="bin", size_bytes=1, sha256="a" * 64)
    scan = Scan(
        scan_id="sc",
        asset_id="a",
        result_json={
            "findings": [
                {"severity": "medium", "title": "old dependency"},
                {"severity": "critical", "deterministic": True, "title": "unsafe opcode"},
            ],
            "checks_run": [],
        },
    )
    verdict = evaluate_scan(asset, scan)
    assert verdict.verdict.value == "BLOCK"
    assert verdict.policy_id == "default"
    assert verdict.policy_version == 1


def test_audit_chain_detects_payload_tampering(test_database):
    with test_database() as session:
        append_audit_event(session, event_type="asset.imported", entity_type="asset", entity_id="a1", payload={"sha256": "a" * 64})
        append_audit_event(session, event_type="scan.completed", entity_type="scan", entity_id="s1", payload={"verdict": "APPROVE"})
        session.commit()
        entries = session.query(AuditLogEntry).order_by(AuditLogEntry.id).all()
        assert entries[1].previous_hash == entries[0].entry_hash
        assert verify_audit_chain(session)
        entries[0].payload = {"sha256": "b" * 64}
        session.commit()
        assert not verify_audit_chain(session)
