from sqlmodel import SQLModel, create_engine, Session
import os

# Use PostgreSQL if DATABASE_URL is provided, otherwise fall back to SQLite
DATABASE_URL = os.getenv("DATABASE_URL")
if DATABASE_URL:
    # PostgreSQL connection
    # Handle Railway's postgres:// URL (needs to be postgresql://)
    if DATABASE_URL.startswith("postgres://"):
        DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)
    engine = create_engine(DATABASE_URL, echo=False)
else:
    # SQLite fallback for local development
    DATABASE_URL = f"sqlite:///{os.path.join(os.path.dirname(__file__), 'app.db')}"
    engine = create_engine(DATABASE_URL, echo=False)

def init_db():
    SQLModel.metadata.create_all(engine)

def get_session():
    return Session(engine)
