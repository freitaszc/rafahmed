"""fixed products

Revision ID: 1a26aa390250
Revises: ba6c118893d9
Create Date: 2025-09-04 12:33:33.815307
"""
from alembic import op
import sqlalchemy as sa

revision = '1a26aa390250'
down_revision = 'ba6c118893d9'
branch_labels = None
depends_on = None


def table_exists(bind, name: str) -> bool:
    insp = sa.inspect(bind)
    return name in insp.get_table_names()


def index_exists(bind, table: str, index_name: str) -> bool:
    insp = sa.inspect(bind)
    return any(ix['name'] == index_name for ix in insp.get_indexes(table))


def fk_exists(bind, table: str, fk_name: str) -> bool:
    insp = sa.inspect(bind)
    return any(fk['name'] == fk_name for fk in insp.get_foreign_keys(table))


def upgrade():
    bind = op.get_bind()

    # --- user_packages (new table) ---
    if not table_exists(bind, 'user_packages'):
        op.create_table(
            'user_packages',
            sa.Column('id', sa.Integer(), primary_key=True, nullable=False),
            sa.Column('user_id', sa.Integer(), nullable=False),
            sa.Column('total', sa.Integer(), nullable=False),
            sa.Column('used', sa.Integer(), nullable=False),
            sa.Column('updated_at', sa.DateTime(), nullable=False),
            sa.ForeignKeyConstraint(['user_id'], ['users.id'], name='fk_user_packages_user_id_users'),
        )

    # index (guarded)
    if not index_exists(bind, 'user_packages', 'ix_user_packages_user_id'):
        with op.batch_alter_table('user_packages', schema=None) as batch_op:
            batch_op.create_index('ix_user_packages_user_id', ['user_id'], unique=True)

    # --- patients (index) ---
    if not index_exists(bind, 'patients', 'ix_patients_cpf'):
        with op.batch_alter_table('patients', schema=None) as batch_op:
            batch_op.create_index('ix_patients_cpf', ['cpf'], unique=False)

    # --- products (columns + index + named FK) ---
    with op.batch_alter_table('products', schema=None) as batch_op:
        # add columns if missing
        for col_name, col in [
            ('doctor_id', sa.Column('doctor_id', sa.Integer(), nullable=True)),
            ('code', sa.Column('code', sa.String(length=64), nullable=True)),
            ('category', sa.Column('category', sa.String(length=80), nullable=True)),
            ('application_route', sa.Column('application_route', sa.String(length=80), nullable=True)),
            ('min_stock', sa.Column('min_stock', sa.Integer(), nullable=True)),
        ]:
            # SQLite batch mode can’t easily “if not exists” columns,
            # but adding the same col twice will crash – so guard using pragma introspection:
            insp = sa.inspect(bind)
            current_cols = [c['name'] for c in insp.get_columns('products')]
            if col_name not in current_cols:
                batch_op.add_column(col)

        # index (guarded)
        if not index_exists(bind, 'products', 'ix_products_doctor_id'):
            batch_op.create_index('ix_products_doctor_id', ['doctor_id'], unique=False)

        # FK (guarded) – NAME IS REQUIRED
        if not fk_exists(bind, 'products', 'fk_products_doctor_id_users'):
            batch_op.create_foreign_key(
                'fk_products_doctor_id_users',
                'users',
                ['doctor_id'],
                ['id']
            )

    # --- users (indexes) ---
    if not index_exists(bind, 'users', 'ix_users_email'):
        with op.batch_alter_table('users', schema=None) as batch_op:
            batch_op.create_index('ix_users_email', ['email'], unique=True)
    if not index_exists(bind, 'users', 'ix_users_username'):
        with op.batch_alter_table('users', schema=None) as batch_op:
            batch_op.create_index('ix_users_username', ['username'], unique=True)


def downgrade():
    bind = op.get_bind()

    # users indexes
    if index_exists(bind, 'users', 'ix_users_username'):
        with op.batch_alter_table('users', schema=None) as batch_op:
            batch_op.drop_index('ix_users_username')
    if index_exists(bind, 'users', 'ix_users_email'):
        with op.batch_alter_table('users', schema=None) as batch_op:
            batch_op.drop_index('ix_users_email')

    # products FK/index/columns
    with op.batch_alter_table('products', schema=None) as batch_op:
        if fk_exists(bind, 'products', 'fk_products_doctor_id_users'):
            batch_op.drop_constraint('fk_products_doctor_id_users', type_='foreignkey')
        if index_exists(bind, 'products', 'ix_products_doctor_id'):
            batch_op.drop_index('ix_products_doctor_id')

        # drop columns if they exist
        insp = sa.inspect(bind)
        current_cols = [c['name'] for c in insp.get_columns('products')]
        for col in ['min_stock', 'application_route', 'category', 'code', 'doctor_id']:
            if col in current_cols:
                batch_op.drop_column(col)

    # patients index
    if index_exists(bind, 'patients', 'ix_patients_cpf'):
        with op.batch_alter_table('patients', schema=None) as batch_op:
            batch_op.drop_index('ix_patients_cpf')

    # user_packages index + table
    if index_exists(bind, 'user_packages', 'ix_user_packages_user_id'):
        with op.batch_alter_table('user_packages', schema=None) as batch_op:
            batch_op.drop_index('ix_user_packages_user_id')
    if table_exists(bind, 'user_packages'):
        op.drop_table('user_packages')
