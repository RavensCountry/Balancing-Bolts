"""
Migration: Add allow_demo_quotes column to organization table
"""
import os
from sqlalchemy import create_engine, text
from sqlmodel import Session
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def run_migration():
    """Add allow_demo_quotes column to organization table"""

    # Use the backend database engine to ensure we're using the same database
    from backend.database import engine

    logger.info("Using application database engine")

    with Session(engine) as session:
        try:
            # Check if we're using PostgreSQL or SQLite
            is_postgres = "postgresql" in str(engine.url)

            if is_postgres:
                # PostgreSQL syntax with IF NOT EXISTS
                logger.info("Adding allow_demo_quotes column to organization table (PostgreSQL)...")
                session.exec(text("""
                    ALTER TABLE organization
                    ADD COLUMN IF NOT EXISTS allow_demo_quotes BOOLEAN DEFAULT TRUE
                """))
                logger.info("Added allow_demo_quotes column")
            else:
                # SQLite doesn't support IF NOT EXISTS, so check first
                logger.info("Checking if allow_demo_quotes column exists (SQLite)...")
                result = session.exec(text("PRAGMA table_info(organization)"))
                columns = [row[1] for row in result.fetchall()]

                if 'allow_demo_quotes' not in columns:
                    logger.info("Adding allow_demo_quotes column to organization table...")
                    session.exec(text("""
                        ALTER TABLE organization
                        ADD COLUMN allow_demo_quotes BOOLEAN DEFAULT 1
                    """))
                    logger.info("Added allow_demo_quotes column")
                else:
                    logger.info("allow_demo_quotes column already exists, skipping")

            session.commit()
            logger.info("SUCCESS: Migration completed successfully!")

        except Exception as e:
            logger.error(f"ERROR: Migration failed: {e}")
            session.rollback()
            raise

if __name__ == "__main__":
    run_migration()
