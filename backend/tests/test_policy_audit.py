import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.db.base import Base
from app.db.models import Asset, AuditLogEntry, Scan
from app.services.audit import append_audit_event, verify_audit_chain
from app.services.policy import evaluate_scan
from app.services import scan_runner
from app.services.attestation import (
    PAYLOAD_TYPE,
    canonical_json,
    dsse_pae,
    sign_dsse,
    verify_dsse,
    verify_signature,
)
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa, utils
from app.main import import_asset
from app.models import ImportAssetRequest


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


def test_policy_does_not_approve_incomplete_checks():
    asset = Asset(asset_id="a2", name="m", source="test", file_format="bin", size_bytes=1, sha256="a" * 64)
    scan = Scan(scan_id="sc2", asset_id="a2", result_json={"findings": [], "checks_run": [{"name": "weight_check", "status": "skipped"}]})
    assert evaluate_scan(asset, scan).verdict.value == "CONDITIONAL"


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


def test_asset_import_persists_pinned_huggingface_source_and_audit(test_database, monkeypatch):
    import app.main as main_module

    monkeypatch.setattr(
        main_module,
        "import_model_file",
        lambda repo, revision, path: ("a_imported", "abc123", 7, "a" * 64, "/tmp/a_imported/model.bin"),
    )
    with test_database() as session:
        response = import_asset(
            ImportAssetRequest(source="huggingface", repo_id="org/model", file_path="weights/model.bin"),
            session,
        )
        assert response.source == "huggingface:org/model@abc123"
        assert response.format == "bin"
        assert session.get(Asset, "a_imported").status == "quarantined"
        assert verify_audit_chain(session)


def test_remote_sandbox_uses_fixed_bucket_and_object_generation(monkeypatch):
    import google.auth.transport.requests
    import google.oauth2.id_token

    class FakeResponse:
        status_code = 200

        @staticmethod
        def json():
            return {"scan_id": "sc_1"}

    class FakeSession:
        def __init__(self, credentials):
            assert credentials == "id-token-credentials"

        @staticmethod
        def post(url, json, timeout):
            assert url == "https://worker.example/scan"
            assert json == {"object_name": "a_1/model#v2.safetensors", "generation": 42}
            assert timeout == (10, 210)
            return FakeResponse()

    monkeypatch.setenv("TRACEON_SANDBOX_URL", "https://worker.example/")
    monkeypatch.setenv("TRACEON_QUARANTINE_BUCKET", "private-bucket")
    monkeypatch.setattr(google.oauth2.id_token, "fetch_id_token_credentials", lambda audience, request: "id-token-credentials")
    monkeypatch.setattr(google.auth.transport.requests, "AuthorizedSession", FakeSession)
    assert scan_runner._run_remote_sandbox("gs://private-bucket/a_1/model%23v2.safetensors?generation=42") == {"scan_id": "sc_1"}


def test_dsse_pae_and_rsa_pss_signature_verification():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    payload = canonical_json({"_type": "https://in-toto.io/Statement/v1", "subject": []})
    pae = dsse_pae(PAYLOAD_TYPE, payload)
    digest = __import__("hashlib").sha256(pae).digest()
    signature = private_key.sign(
        digest,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=hashes.SHA256().digest_size),
        utils.Prehashed(hashes.SHA256()),
    )
    verify_signature(private_key.public_key(), "RSA_SIGN_PSS_2048_SHA256", signature, digest)


def test_dsse_round_trip_matches_cloud_kms_digest_signing(monkeypatch):
    from types import SimpleNamespace

    from google.cloud import kms_v1

    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_pem = private_key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("ascii")

    class FakeKmsClient:
        def asymmetric_sign(self, request):
            signature = private_key.sign(
                request["digest"]["sha256"],
                padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=hashes.SHA256().digest_size),
                utils.Prehashed(hashes.SHA256()),
            )
            return SimpleNamespace(signature=signature)

        @staticmethod
        def get_public_key(request):
            return SimpleNamespace(
                pem=public_pem,
                algorithm=SimpleNamespace(name="RSA_SIGN_PSS_2048_SHA256"),
            )

    monkeypatch.setenv(
        "TRACEON_KMS_KEY_VERSION",
        "projects/test/locations/test/keyRings/test/cryptoKeys/test/cryptoKeyVersions/1",
    )
    monkeypatch.setattr(kms_v1, "KeyManagementServiceClient", FakeKmsClient)
    bom = {"bomFormat": "CycloneDX", "specVersion": "1.7"}
    statement = {
        "_type": "https://in-toto.io/Statement/v1",
        "subject": [{"name": "tiny.bin", "digest": {"sha256": "a" * 64}}],
        "predicate": {
            "bomDigest": {"sha256": __import__("hashlib").sha256(canonical_json(bom)).hexdigest()},
            "expiresAt": "2099-01-01T00:00:00Z",
        },
    }
    envelope = sign_dsse(statement)
    envelope["bom"] = bom
    assert verify_dsse(envelope, "a" * 64) == (True, None)
    envelope["bom"]["specVersion"] = "tampered"
    assert verify_dsse(envelope, "a" * 64)[0] is False
