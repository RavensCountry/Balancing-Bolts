"""
Migration: Create missing tables (organization, vendorcredential, quoterequest, quote)
"""
from sqlmodel import SQLModel
from backend.database import engine
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def run_migration():
    """Create all missing tables defined in models"""

    try:
        logger.info("Creating all missing tables from SQLModel definitions...")

        # Import all models to ensure they're registered with SQLModel
        from backend.models import (
            Organization, User, Property, UserPropertyAccess,
            InventoryItem, Invoice, ActivityLog, Embedding,
            ResmanToken, VendorCredential, QuoteRequest, Quote
        )

        # Create all tables (will skip existing ones)
        SQLModel.metadata.create_all(engine)

        logger.info("SUCCESS: All missing tables created successfully!")

        # Verify the tables were created
        from sqlalchemy import inspect
        inspector = inspect(engine)
        tables = inspector.get_table_names()

        logger.info("\nCurrent tables in database:")
        for table in sorted(tables):
            logger.info(f"  - {table}")

    except Exception as e:
        logger.error(f"ERROR: Migration failed: {e}")
        raise

if __name__ == "__main__":
    run_migration()
