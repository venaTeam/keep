"""feat: Add user_preset_column_config table for per-user view settings

Revision ID: a1b2c3d4e5f6
Revises: 9dd1be4539e0
Create Date: 2026-02-18 16:55:00.000000

"""

import sqlalchemy as sa
import sqlmodel
from alembic import op

# revision identifiers, used by Alembic.
revision = "a1b2c3d4e5f6"
down_revision = "9dd1be4539e0"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "userpresetcolumnconfig",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column(
            "tenant_id", sqlmodel.sql.sqltypes.AutoString(), nullable=False
        ),
        sa.Column("preset_id", sa.Uuid(), nullable=False),
        sa.Column(
            "user_email", sqlmodel.sql.sqltypes.AutoString(), nullable=False
        ),
        sa.Column("column_visibility", sa.JSON(), nullable=True),
        sa.Column("column_order", sa.JSON(), nullable=True),
        sa.Column("column_rename_mapping", sa.JSON(), nullable=True),
        sa.Column("column_time_formats", sa.JSON(), nullable=True),
        sa.Column("column_list_formats", sa.JSON(), nullable=True),
        sa.ForeignKeyConstraint(
            ["tenant_id"],
            ["tenant.id"],
        ),
        sa.ForeignKeyConstraint(
            ["preset_id"],
            ["preset.id"],
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("tenant_id", "preset_id", "user_email"),
    )
    op.create_index(
        op.f("ix_userpresetcolumnconfig_tenant_id"),
        "userpresetcolumnconfig",
        ["tenant_id"],
        unique=False,
    )
    op.create_index(
        op.f("ix_userpresetcolumnconfig_preset_id"),
        "userpresetcolumnconfig",
        ["preset_id"],
        unique=False,
    )
    op.create_index(
        op.f("ix_userpresetcolumnconfig_user_email"),
        "userpresetcolumnconfig",
        ["user_email"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index(
        op.f("ix_userpresetcolumnconfig_user_email"),
        table_name="userpresetcolumnconfig",
    )
    op.drop_index(
        op.f("ix_userpresetcolumnconfig_preset_id"),
        table_name="userpresetcolumnconfig",
    )
    op.drop_index(
        op.f("ix_userpresetcolumnconfig_tenant_id"),
        table_name="userpresetcolumnconfig",
    )
    op.drop_table("userpresetcolumnconfig")
