"""empty message

Revision ID: ff809cba89ee
Revises: 044bc41eb934
Create Date: 2021-10-26 12:41:47.905797

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'ff809cba89ee'
down_revision = '044bc41eb934'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.add_column('homework', sa.Column('title', sa.String(length=128), nullable=True))
    op.add_column('homework', sa.Column('description', sa.String(), nullable=True))
    op.add_column('homework', sa.Column('limit_date', sa.DateTime(), nullable=True))
    op.add_column('homework', sa.Column('status', sa.String(), nullable=True))
    op.add_column('homework', sa.Column('student_comment', sa.String(), nullable=True))
    op.add_column('homework', sa.Column('grade', sa.DECIMAL(precision=5, scale=2), nullable=True))
    op.add_column('homework', sa.Column('date_sent', sa.DateTime(), nullable=True))
    op.add_column('homework', sa.Column('file_url', sa.String(), nullable=True))
    op.drop_index('ix_homework_email', table_name='homework')
    op.drop_index('ix_homework_username', table_name='homework')
    op.drop_column('homework', 'email')
    op.drop_column('homework', 'name')
    op.drop_column('homework', 'username')
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.add_column('homework', sa.Column('username', sa.VARCHAR(length=64), nullable=True))
    op.add_column('homework', sa.Column('name', sa.VARCHAR(length=64), nullable=True))
    op.add_column('homework', sa.Column('email', sa.VARCHAR(length=64), nullable=True))
    op.create_index('ix_homework_username', 'homework', ['username'], unique=False)
    op.create_index('ix_homework_email', 'homework', ['email'], unique=False)
    op.drop_column('homework', 'file_url')
    op.drop_column('homework', 'date_sent')
    op.drop_column('homework', 'grade')
    op.drop_column('homework', 'student_comment')
    op.drop_column('homework', 'status')
    op.drop_column('homework', 'limit_date')
    op.drop_column('homework', 'description')
    op.drop_column('homework', 'title')
    # ### end Alembic commands ###