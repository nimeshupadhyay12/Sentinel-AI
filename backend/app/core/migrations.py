"""Additive, idempotent upgrade of older SQLite/PostgreSQL databases."""
from sqlalchemy import inspect, text
from app.core.database import Base

# New nullable columns added to tables that may already exist. Table and column
# names are fixed literals from this file, never user input.
ADDED_COLUMNS = {
    'threat_analysis_records': {
        'attacker_state_probs': 'JSON',
        'adaptation_score': 'FLOAT DEFAULT 0',
        'response_effectiveness': 'FLOAT DEFAULT 0',
        'attacker_state': "VARCHAR DEFAULT 'UNKNOWN'",
        'score_breakdown': 'JSON',
    },
    'alerts': {'score_breakdown': 'JSON'},
    'secure_audit_logs': {'signer_key_id': 'VARCHAR(32)'},
}


def upgrade_schema(engine):
    # Import registers all models before create_all. Existing rows are retained.
    from app.models import models  # noqa: F401
    with engine.begin() as connection:
        if connection.dialect.name == 'postgresql':
            # Serialize concurrent app-worker migrations for this database.
            connection.execute(text('SELECT pg_advisory_xact_lock(72819346)'))
        Base.metadata.create_all(connection)
        inspector = inspect(connection)
        for table, columns in ADDED_COLUMNS.items():
            existing = {c['name'] for c in inspector.get_columns(table)}
            for name, definition in columns.items():
                if name not in existing:
                    connection.execute(text(f'ALTER TABLE {table} ADD COLUMN {name} {definition}'))
