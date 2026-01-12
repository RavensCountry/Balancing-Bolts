"""
Database migration script to create/update tables
Run this script to ensure all database tables are created
"""
from database import init_db, engine
from models import (
    User, Property, UserPropertyAccess, InventoryItem, Invoice,
    ActivityLog, Embedding, ResmanToken, VendorCredential,
    QuoteRequest, Quote
)
from sqlmodel import SQLModel
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def migrate():
    """Create all database tables"""
    logger.info("Starting database migration...")
    logger.info(f"Using database: {engine.url}")

    try:
        # Create all tables
        SQLModel.metadata.create_all(engine)
        logger.info("✓ All tables created successfully!")

        # List created tables
        logger.info("\nCreated/verified tables:")
        for table in SQLModel.metadata.sorted_tables:
            logger.info(f"  - {table.name}")

    except Exception as e:
        logger.error(f"Error during migration: {e}")
        raise

if __name__ == "__main__":
    migrate()
