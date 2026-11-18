"""Database engine and request-scoped SQLAlchemy sessions."""

import os
from collections.abc import Iterator
from pathlib import Path

from sqlalchemy import create_engine, event
from sqlalchemy.engine import make_url
from sqlalchemy.orm import Session, sessionmaker


def _default_database_url() -> str:
    database_path = Path(__file__).resolve().parents[2] / "traceon.db"
    return f"sqlite:///{database_path.as_posix()}"


DATABASE_URL = os.getenv("TRACEON_DATABASE_URL", _default_database_url())
url = make_url(DATABASE_URL)
engine_options: dict[str, object] = {"pool_pre_ping": True}
if url.get_backend_name() == "sqlite":
    engine_options["connect_args"] = {"check_same_thread": False}

engine = create_engine(DATABASE_URL, **engine_options)

if url.get_backend_name() == "sqlite":

    @event.listens_for(engine, "connect")
    def _enable_sqlite_foreign_keys(connection, connection_record) -> None:
        cursor = connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()


SessionLocal = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)


def get_session() -> Iterator[Session]:
    with SessionLocal() as session:
        yield session
