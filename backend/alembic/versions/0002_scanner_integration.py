"""Add backend file location and scanner result ID fields."""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "0002_scanner_integration"
down_revision: Union[str, None] = "0001_initial_database"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column("assets", sa.Column("storage_path", sa.Text(), nullable=True))
    op.add_column("scans", sa.Column("scanner_scan_id", sa.String(length=64), nullable=True))
    op.create_index("ix_scans_scanner_scan_id", "scans", ["scanner_scan_id"], unique=True)


def downgrade() -> None:
    op.drop_index("ix_scans_scanner_scan_id", table_name="scans")
    op.drop_column("scans", "scanner_scan_id")
    op.drop_column("assets", "storage_path")
