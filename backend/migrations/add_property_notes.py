"""
Migration: Add notes column to property table
"""
import logging
from sqlmodel import Session
from sqlalchemy import text

logger = logging.getLogger(__name__)

def run_migration():
    """Add notes column to property table"""
    logger.info("Using application database engine")
    from backend.database import engine

    with Session(engine) as session:
        try:
            # Check if we're using PostgreSQL or SQLite
            is_postgres = "postgresql" in str(engine.url)

            if is_postgres:
                logger.info("Adding notes column to property table (PostgreSQL)...")
                session.exec(text("""
                    ALTER TABLE property
                    ADD COLUMN IF NOT EXISTS notes TEXT
                """))
            else:
                # SQLite doesn't support IF NOT EXISTS in ALTER TABLE
                # Check if column exists first
                logger.info("Adding notes column to property table (SQLite)...")
                result = session.exec(text("PRAGMA table_info(property)"))
                columns = [row[1] for row in result.fetchall()]

                if 'notes' not in columns:
                    session.exec(text("""
                        ALTER TABLE property
                        ADD COLUMN notes TEXT
                    """))
                    logger.info("Added notes column")
                else:
                    logger.info("Column notes already exists, skipping")

            session.commit()
            logger.info("SUCCESS: Migration completed successfully!")

        except Exception as e:
            session.rollback()
            logger.error(f"Migration failed: {e}")
            raise

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    run_migration()
