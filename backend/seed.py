"""Insert a deterministic, harmless scanner corpus asset for local development."""

import hashlib
from pathlib import Path

from app.db.models import Asset
from app.db.session import SessionLocal
from app.services.audit import append_audit_event


def main() -> None:
    repository_root = Path(__file__).resolve().parents[1]
    artifact = repository_root / "scanner" / "corpus" / "clean.pkl"
    if not artifact.is_file():
        raise SystemExit(f"Expected local scanner corpus file at {artifact}")
    digest = hashlib.sha256(artifact.read_bytes()).hexdigest()
    asset_id = "a_seed_clean"
    with SessionLocal() as session:
        existing = session.get(Asset, asset_id)
        if existing:
            print(f"Seed asset already exists: {asset_id}")
            return
        asset = Asset(
            asset_id=asset_id,
            name=artifact.name,
            source="synthetic-seed:scanner/corpus/clean.pkl",
            file_format="pickle",
            size_bytes=artifact.stat().st_size,
            sha256=digest,
            storage_path=str(artifact),
            status="quarantined",
        )
        session.add(asset)
        append_audit_event(
            session,
            event_type="asset.seeded",
            entity_type="asset",
            entity_id=asset_id,
            payload={"sha256": digest, "source": asset.source},
        )
        session.commit()
    print(f"Seeded {asset_id} ({digest})")


if __name__ == "__main__":
    main()
