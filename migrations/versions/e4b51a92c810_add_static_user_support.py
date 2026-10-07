"""add static user support

Revision ID: e4b51a92c810
Revises: 317e2da95c63
Create Date: 2026-09-16 11:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


# revision identifiers, used by Alembic.
revision: str = 'e4b51a92c810'
down_revision: Union[str, Sequence[str], None] = '317e2da95c63'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    connection_type_enum = postgresql.ENUM('pppoe', 'static', name='connection_type')
    connection_type_enum.create(op.get_bind(), checkfirst=True)

    op.add_column(
        'customers',
        sa.Column(
            'connection_type',
            sa.Enum('pppoe', 'static', name='connection_type'),
            server_default='pppoe',
            nullable=False,
        ),
    )
    op.add_column('customers', sa.Column('static_ip', sa.String(length=45), nullable=True))


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_column('customers', 'static_ip')
    op.drop_column('customers', 'connection_type')

    connection_type_enum = postgresql.ENUM('pppoe', 'static', name='connection_type')
    connection_type_enum.drop(op.get_bind(), checkfirst=True)
