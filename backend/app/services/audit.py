"""Append-only hash-chained audit log helpers."""

import hashlib
import json

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..db.models import AuditLogEntry, utc_now


def _canonical_json(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def append_audit_event(
    session: Session,
    *,
    event_type: str,
    entity_type: str,
    entity_id: str,
    payload: dict,
) -> AuditLogEntry:
    """Hash the canonical event body together with the previous entry hash."""

    previous = session.scalar(select(AuditLogEntry).order_by(AuditLogEntry.id.desc()).limit(1))
    previous_hash = previous.entry_hash if previous else None
    occurred_at = utc_now()
    body = {
        "occurred_at": occurred_at.isoformat(),
        "event_type": event_type,
        "entity_type": entity_type,
        "entity_id": entity_id,
        "payload": payload,
        "previous_hash": previous_hash,
    }
    entry_hash = hashlib.sha256(_canonical_json(body)).hexdigest()
    entry = AuditLogEntry(
        occurred_at=occurred_at,
        event_type=event_type,
        entity_type=entity_type,
        entity_id=entity_id,
        payload=payload,
        previous_hash=previous_hash,
        entry_hash=entry_hash,
    )
    session.add(entry)
    session.flush()
    return entry


def verify_audit_chain(session: Session) -> bool:
    """Return false if an entry, its payload, or a link was changed."""

    previous_hash = None
    entries = session.scalars(select(AuditLogEntry).order_by(AuditLogEntry.id)).all()
    for entry in entries:
        if entry.previous_hash != previous_hash:
            return False
        body = {
            "occurred_at": entry.occurred_at.isoformat(),
            "event_type": entry.event_type,
            "entity_type": entry.entity_type,
            "entity_id": entry.entity_id,
            "payload": entry.payload,
            "previous_hash": entry.previous_hash,
        }
        digest = hashlib.sha256(_canonical_json(body)).hexdigest()
        if digest != entry.entry_hash:
            return False
        previous_hash = entry.entry_hash
    return True
