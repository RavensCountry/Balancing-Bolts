"""
Migration script to add organization multi-tenancy
Run this to add organization table and organization_id columns
"""
import os
import sys

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from backend.database import engine
from sqlalchemy import text
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def migrate():
    """Add organization table and foreign keys"""
    logger.info("Starting organization multi-tenancy migration...")

    migrations = [
        # Create organization table
        """
        CREATE TABLE IF NOT EXISTS organization (
            id SERIAL PRIMARY KEY,
            name VARCHAR NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        """,

        # Add organization_id to user table
        "ALTER TABLE \"user\" ADD COLUMN IF NOT EXISTS organization_id INTEGER REFERENCES organization(id);",

        # Add organization_id to property table
        "ALTER TABLE property ADD COLUMN IF NOT EXISTS organization_id INTEGER REFERENCES organization(id);",

        # Create a default organization for existing data
        "INSERT INTO organization (name) VALUES ('Default Organization') ON CONFLICT DO NOTHING;",

        # Assign existing users to default organization (id=1)
        "UPDATE \"user\" SET organization_id = 1 WHERE organization_id IS NULL;",

        # Assign existing properties to default organization
        "UPDATE property SET organization_id = 1 WHERE organization_id IS NULL;",
    ]

    try:
        with engine.connect() as conn:
            for sql in migrations:
                logger.info(f"Executing migration...")
                conn.execute(text(sql))
                conn.commit()

        logger.info("✓ Organization migration completed successfully!")
        logger.info("All existing users and properties have been assigned to 'Default Organization'")

    except Exception as e:
        logger.error(f"Error during migration: {e}")
        raise

if __name__ == "__main__":
    migrate()
