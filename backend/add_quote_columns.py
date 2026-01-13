"""
Migration script to add missing columns to quoterequest table
Run this to add invoice_id and is_auto_generated columns
"""
import os
import sys

# Add parent directory to path so we can import backend modules
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from backend.database import engine
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def migrate():
    """Add missing columns to quoterequest table"""
    logger.info("Starting migration to add columns to quoterequest table...")

    # SQL statements to add the missing columns
    migrations = [
        "ALTER TABLE quoterequest ADD COLUMN IF NOT EXISTS invoice_id INTEGER;",
        "ALTER TABLE quoterequest ADD COLUMN IF NOT EXISTS is_auto_generated BOOLEAN DEFAULT FALSE;",
    ]

    try:
        with engine.connect() as conn:
            for sql in migrations:
                logger.info(f"Executing: {sql}")
                conn.execute(sql)
                conn.commit()

        logger.info("✓ Migration completed successfully!")
        logger.info("The quoterequest table now has invoice_id and is_auto_generated columns.")

    except Exception as e:
        logger.error(f"Error during migration: {e}")
        raise

if __name__ == "__main__":
    migrate()
