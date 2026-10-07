"""add router command queue and router devices

Revision ID: 7c1d2e9a4b30
Revises: e4b51a92c810
Create Date: 2026-10-07 12:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


# revision identifiers, used by Alembic.
revision: str = '7c1d2e9a4b30'
down_revision: Union[str, Sequence[str], None] = 'e4b51a92c810'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    status_enum = postgresql.ENUM('pending', 'sent', 'done', 'failed', name='router_command_status', create_type=False)
    status_enum.create(op.get_bind(), checkfirst=True)

    op.create_table(
        'router_commands',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('description', sa.String(length=255), nullable=False),
        sa.Column('script', sa.Text(), nullable=False),
        sa.Column('status', status_enum, nullable=False),
        sa.Column('attempts', sa.Integer(), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('sent_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('finished_at', sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index(op.f('ix_router_commands_status'), 'router_commands', ['status'], unique=False)

    op.create_table(
        'router_devices',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('name', sa.String(length=64), nullable=False),
        sa.Column('token', sa.String(length=64), nullable=False),
        sa.Column('last_seen_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('last_ip', sa.String(length=45), nullable=True),
        sa.Column('version', sa.String(length=64), nullable=True),
        sa.Column('board', sa.String(length=64), nullable=True),
        sa.Column('uptime', sa.String(length=32), nullable=True),
        sa.Column('cpu_load', sa.Integer(), nullable=True),
        sa.Column('active_usernames', sa.JSON(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('token'),
    )


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_table('router_devices')
    op.drop_index(op.f('ix_router_commands_status'), table_name='router_commands')
    op.drop_table('router_commands')
    postgresql.ENUM(name='router_command_status').drop(op.get_bind(), checkfirst=True)
