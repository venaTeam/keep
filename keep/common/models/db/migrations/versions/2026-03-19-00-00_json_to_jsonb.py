"""json_to_jsonb

Revision ID: json_to_jsonb
Revises: a1b2c3d4e5f6
Create Date: 2026-03-19 00:00:00.000000

"""

import sqlalchemy as sa
import sqlmodel
from alembic import op

# revision identifiers, used by Alembic.
revision = "json_to_jsonb"
down_revision = "a1b2c3d4e5f6"
branch_labels = None
depends_on = None


def upgrade() -> None:
    bind = op.get_bind()
    if bind.dialect.name != "postgresql":
        return  # SQLite/MySQL: no-op, JSON stays as-is

    # Convert JSON → JSONB (acquires ACCESS EXCLUSIVE lock per table)
    op.execute("ALTER TABLE alert ALTER COLUMN event TYPE JSONB USING event::JSONB")
    op.execute(
        "ALTER TABLE alertenrichment ALTER COLUMN enrichments TYPE JSONB USING enrichments::JSONB"
    )
    op.execute(
        "ALTER TABLE alertdeduplicationrule ALTER COLUMN fingerprint_fields TYPE JSONB USING fingerprint_fields::JSONB"
    )
    op.execute(
        "ALTER TABLE alertdeduplicationrule ALTER COLUMN ignore_fields TYPE JSONB USING ignore_fields::JSONB"
    )
    op.execute(
        "ALTER TABLE alertraw ALTER COLUMN raw_alert TYPE JSONB USING raw_alert::JSONB"
    )

    # GIN indexes — accelerate @> / ? operators used by the CEL-to-SQL layer
    op.create_index(
        "ix_alert_event_gin", "alert", ["event"], postgresql_using="gin"
    )
    op.create_index(
        "ix_alertenrichment_enrichments_gin",
        "alertenrichment",
        ["enrichments"],
        postgresql_using="gin",
    )


def downgrade() -> None:
    bind = op.get_bind()
    if bind.dialect.name != "postgresql":
        return

    op.drop_index("ix_alertenrichment_enrichments_gin", table_name="alertenrichment")
    op.drop_index("ix_alert_event_gin", table_name="alert")

    op.execute(
        "ALTER TABLE alertraw ALTER COLUMN raw_alert TYPE JSON USING raw_alert::JSON"
    )
    op.execute(
        "ALTER TABLE alertdeduplicationrule ALTER COLUMN ignore_fields TYPE JSON USING ignore_fields::JSON"
    )
    op.execute(
        "ALTER TABLE alertdeduplicationrule ALTER COLUMN fingerprint_fields TYPE JSON USING fingerprint_fields::JSON"
    )
    op.execute(
        "ALTER TABLE alertenrichment ALTER COLUMN enrichments TYPE JSON USING enrichments::JSON"
    )
    op.execute("ALTER TABLE alert ALTER COLUMN event TYPE JSON USING event::JSON")
