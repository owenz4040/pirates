"""add missing hotspot payment and voucher columns

Revision ID: 33098787898f
Revises: 22098787898e
Create Date: 2026-11-22 03:30:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '33098787898f'
down_revision: Union[str, Sequence[str], None] = '22098787898e'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Additive schema upgrade for hotspot payments and vouchers."""
    # 1. HotspotVoucher: password and customer_payment_id
    with op.batch_alter_table('saas_hotspot_vouchers') as batch_op:
        try:
            batch_op.add_column(sa.Column('password', sa.String(length=64), nullable=True))
        except Exception:
            pass
        try:
            batch_op.add_column(sa.Column('customer_payment_id', sa.String(length=36), nullable=True))
        except Exception:
            pass
        try:
            batch_op.create_index(
                op.f('ix_saas_hotspot_vouchers_customer_payment_id'),
                ['customer_payment_id'],
                unique=False
            )
        except Exception:
            pass

    # 2. CustomerPayment: package_id, router_id, provider_reference, client_mac, client_ip, link_login_only, paid_at
    with op.batch_alter_table('saas_customer_payments') as batch_op:
        for col_name, col_type in [
            ('package_id', sa.String(length=36)),
            ('router_id', sa.String(length=36)),
            ('provider_reference', sa.String(length=128)),
            ('client_mac', sa.String(length=32)),
            ('client_ip', sa.String(length=45)),
            ('link_login_only', sa.String(length=255)),
            ('paid_at', sa.DateTime(timezone=True)),
        ]:
            try:
                batch_op.add_column(sa.Column(col_name, col_type, nullable=True))
            except Exception:
                pass

        for idx_name, col_names in [
            ('ix_saas_customer_payments_package_id', ['package_id']),
            ('ix_saas_customer_payments_router_id', ['router_id']),
            ('ix_saas_customer_payments_provider_reference', ['provider_reference']),
        ]:
            try:
                batch_op.create_index(op.f(idx_name), col_names, unique=False)
            except Exception:
                pass


def downgrade() -> None:
    """Downgrade schema."""
    with op.batch_alter_table('saas_customer_payments') as batch_op:
        for idx in [
            'ix_saas_customer_payments_provider_reference',
            'ix_saas_customer_payments_router_id',
            'ix_saas_customer_payments_package_id',
        ]:
            try:
                batch_op.drop_index(op.f(idx))
            except Exception:
                pass
        for col in [
            'paid_at', 'link_login_only', 'client_ip', 'client_mac',
            'provider_reference', 'router_id', 'package_id',
        ]:
            try:
                batch_op.drop_column(col)
            except Exception:
                pass

    with op.batch_alter_table('saas_hotspot_vouchers') as batch_op:
        try:
            batch_op.drop_index(op.f('ix_saas_hotspot_vouchers_customer_payment_id'))
        except Exception:
            pass
        try:
            batch_op.drop_column('customer_payment_id')
        except Exception:
            pass
        try:
            batch_op.drop_column('password')
        except Exception:
            pass
