"""docker blob links (blobs are only served through repositories they belong to)

Revision ID: 0005
Revises: 0004
Create Date: 2026-10-07 10:30:00.000000
"""
from alembic import op
import sqlalchemy as sa


revision = '0005'
down_revision = '0004'
branch_labels = None
depends_on = None


def upgrade():
    # existing manifests are linked lazily on first access (their JSON lives in the blob store)
    op.create_table(
        'docker_blob_link',
        sa.Column('repository_id', sa.Integer(), nullable=False),
        sa.Column('digest', sa.String(length=100), nullable=False),
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(['repository_id'], ['repository.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('repository_id', 'digest'),
    )


def downgrade():
    op.drop_table('docker_blob_link')
