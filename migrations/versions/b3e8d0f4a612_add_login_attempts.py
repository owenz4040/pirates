"""add login attempts for brute-force lockout

Revision ID: b3e8d0f4a612
Revises: 9a4f1c2d7e55
Create Date: 2026-10-08 10:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'b3e8d0f4a612'
down_revision: Union[str, Sequence[str], None] = '9a4f1c2d7e55'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    op.create_table(
        'login_attempts',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('ip', sa.String(length=45), nullable=False),
        sa.Column('username', sa.String(length=128), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index(op.f('ix_login_attempts_ip'), 'login_attempts', ['ip'], unique=False)
    op.create_index(op.f('ix_login_attempts_created_at'), 'login_attempts', ['created_at'], unique=False)


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_index(op.f('ix_login_attempts_created_at'), table_name='login_attempts')
    op.drop_index(op.f('ix_login_attempts_ip'), table_name='login_attempts')
    op.drop_table('login_attempts')
