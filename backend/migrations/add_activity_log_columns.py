"""
Migration: Add ip_address, page, and target columns to activitylog table
"""
from sqlmodel import create_engine, Session, text
from backend.database import DATABASE_URL
import os

def run_migration():
    """Add new columns to activitylog table"""

    # Get database URL
    db_url = os.getenv("DATABASE_URL")
    if db_url:
        # Handle Railway's postgres:// URL (needs to be postgresql://)
        if db_url.startswith("postgres://"):
            db_url = db_url.replace("postgres://", "postgresql://", 1)
    else:
        # SQLite fallback
        db_url = f"sqlite:///{os.path.join(os.path.dirname(__file__), '..', 'app.db')}"

    engine = create_engine(db_url, echo=True)

    with Session(engine) as session:
        try:
            # Check if we're using PostgreSQL or SQLite
            is_postgres = "postgresql" in db_url

            if is_postgres:
                # PostgreSQL syntax
                print("Running PostgreSQL migration...")

                # Add ip_address column
                session.exec(text("""
                    ALTER TABLE activitylog
                    ADD COLUMN IF NOT EXISTS ip_address VARCHAR(45)
                """))

                # Add page column
                session.exec(text("""
                    ALTER TABLE activitylog
                    ADD COLUMN IF NOT EXISTS page VARCHAR(255)
                """))

                # Add target column
                session.exec(text("""
                    ALTER TABLE activitylog
                    ADD COLUMN IF NOT EXISTS target VARCHAR(255)
                """))
            else:
                # SQLite syntax
                print("Running SQLite migration...")

                # Check if columns exist first
                result = session.exec(text("PRAGMA table_info(activitylog)"))
                columns = [row[1] for row in result.fetchall()]

                if 'ip_address' not in columns:
                    session.exec(text("""
                        ALTER TABLE activitylog
                        ADD COLUMN ip_address VARCHAR(45)
                    """))
                    print("Added ip_address column")

                if 'page' not in columns:
                    session.exec(text("""
                        ALTER TABLE activitylog
                        ADD COLUMN page VARCHAR(255)
                    """))
                    print("Added page column")

                if 'target' not in columns:
                    session.exec(text("""
                        ALTER TABLE activitylog
                        ADD COLUMN target VARCHAR(255)
                    """))
                    print("Added target column")

            session.commit()
            print("SUCCESS: Migration completed successfully!")

        except Exception as e:
            print(f"ERROR: Migration failed: {e}")
            session.rollback()
            raise

if __name__ == "__main__":
    run_migration()
