"""hotspot_security_remediation

Revision ID: 22098787898e
Revises: 11098787898d
Create Date: 2026-11-22 02:22:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '22098787898e'
down_revision: Union[str, Sequence[str], None] = '11098787898d'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Additive schema upgrade for hotspot billing security remediation."""
    # 1. CustomerPayment: checkout_request_id column + index + unique constraint
    op.add_column(
        'saas_customer_payments',
        sa.Column('checkout_request_id', sa.String(length=64), nullable=True)
    )
    op.create_index(
        op.f('ix_saas_customer_payments_checkout_request_id'),
        'saas_customer_payments',
        ['checkout_request_id'],
        unique=False
    )
    try:
        op.create_unique_constraint(
            'uq_customer_payment_tenant_checkout_id',
            'saas_customer_payments',
            ['tenant_id', 'checkout_request_id']
        )
    except Exception:
        pass

    # 2. TenantPaymentConfig: callback tokens for secure M-Pesa webhook authentication
    op.add_column(
        'tenant_payment_configs',
        sa.Column('mpesa_callback_token_encrypted', sa.Text(), nullable=True)
    )
    op.add_column(
        'tenant_payment_configs',
        sa.Column('mpesa_callback_token_hash', sa.String(length=64), nullable=True)
    )
    op.add_column(
        'tenant_payment_configs',
        sa.Column('previous_callback_token_hash', sa.String(length=64), nullable=True)
    )

    # 3. HotspotVoucher: router_command_id linkage
    op.add_column(
        'saas_hotspot_vouchers',
        sa.Column('router_command_id', sa.String(length=36), nullable=True)
    )
    op.create_index(
        op.f('ix_saas_hotspot_vouchers_router_command_id'),
        'saas_hotspot_vouchers',
        ['router_command_id'],
        unique=False
    )

    # 4. RouterCommand: voucher_id linkage
    op.add_column(
        'saas_router_commands',
        sa.Column('voucher_id', sa.String(length=36), nullable=True)
    )
    op.create_index(
        op.f('ix_saas_router_commands_voucher_id'),
        'saas_router_commands',
        ['voucher_id'],
        unique=False
    )


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_index(op.f('ix_saas_router_commands_voucher_id'), table_name='saas_router_commands')
    op.drop_column('saas_router_commands', 'voucher_id')

    op.drop_index(op.f('ix_saas_hotspot_vouchers_router_command_id'), table_name='saas_hotspot_vouchers')
    op.drop_column('saas_hotspot_vouchers', 'router_command_id')

    op.drop_column('tenant_payment_configs', 'previous_callback_token_hash')
    op.drop_column('tenant_payment_configs', 'mpesa_callback_token_hash')
    op.drop_column('tenant_payment_configs', 'mpesa_callback_token_encrypted')

    try:
        op.drop_constraint('uq_customer_payment_tenant_checkout_id', 'saas_customer_payments', type_='unique')
    except Exception:
        pass
    op.drop_index(op.f('ix_saas_customer_payments_checkout_request_id'), table_name='saas_customer_payments')
    op.drop_column('saas_customer_payments', 'checkout_request_id')
