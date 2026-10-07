"""import existing router users: optional phone, router secret snapshot

Revision ID: 9a4f1c2d7e55
Revises: 7c1d2e9a4b30
Create Date: 2026-10-07 21:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '9a4f1c2d7e55'
down_revision: Union[str, Sequence[str], None] = '7c1d2e9a4b30'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    op.alter_column('customers', 'phone_number', existing_type=sa.String(length=20), nullable=True)
    op.add_column('router_devices', sa.Column('router_secrets', sa.JSON(), nullable=True))
    op.add_column('router_devices', sa.Column('router_profiles', sa.JSON(), nullable=True))
    op.add_column('router_devices', sa.Column('secrets_requested_at', sa.DateTime(timezone=True), nullable=True))
    op.add_column('router_devices', sa.Column('secrets_reported_at', sa.DateTime(timezone=True), nullable=True))


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_column('router_devices', 'secrets_reported_at')
    op.drop_column('router_devices', 'secrets_requested_at')
    op.drop_column('router_devices', 'router_profiles')
    op.drop_column('router_devices', 'router_secrets')
    op.alter_column('customers', 'phone_number', existing_type=sa.String(length=20), nullable=False)
