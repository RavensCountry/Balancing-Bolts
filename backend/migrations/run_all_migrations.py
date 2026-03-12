"""
Run all pending migrations in order
"""
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def run_all_migrations():
    """Run all migrations in the correct order"""
    logger.info("=" * 60)
    logger.info("STARTING ALL MIGRATIONS")
    logger.info("=" * 60)

    migrations = [
        ("Create missing tables", "backend.migrations.create_missing_tables"),
        ("Add activity log columns", "backend.migrations.add_activity_log_columns"),
        ("Add allow_demo_quotes to organization", "backend.migrations.add_allow_demo_quotes"),
    ]

    for name, module_path in migrations:
        logger.info("")
        logger.info("=" * 60)
        logger.info(f"Running migration: {name}")
        logger.info("=" * 60)

        try:
            # Import and run the migration
            module_parts = module_path.split('.')
            module = __import__(module_path, fromlist=[module_parts[-1]])
            module.run_migration()
            logger.info(f"✓ SUCCESS: {name} completed")
        except Exception as e:
            logger.error(f"✗ FAILED: {name} - {e}")
            # Continue with other migrations even if one fails
            continue

    logger.info("")
    logger.info("=" * 60)
    logger.info("ALL MIGRATIONS COMPLETED")
    logger.info("=" * 60)

if __name__ == "__main__":
    run_all_migrations()
