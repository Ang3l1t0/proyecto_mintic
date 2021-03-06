"""empty message

Revision ID: 32faa9ca964c
Revises: ff809cba89ee
Create Date: 2021-10-26 12:44:08.864096

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '32faa9ca964c'
down_revision = 'ff809cba89ee'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_column('homework', 'last_name')
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.add_column('homework', sa.Column('last_name', sa.VARCHAR(length=64), nullable=True))
    # ### end Alembic commands ###
