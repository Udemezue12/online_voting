"""Modifications were made

Revision ID: 60f8c94bb51e
Revises: 23947bdfd19f
Create Date: 2024-12-10 11:25:55.988050

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '60f8c94bb51e'
down_revision = '23947bdfd19f'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('vote', schema=None) as batch_op:
        batch_op.drop_column('hashed_ip')

    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('vote', schema=None) as batch_op:
        batch_op.add_column(sa.Column('hashed_ip', sa.VARCHAR(length=64), nullable=False))

    # ### end Alembic commands ###
