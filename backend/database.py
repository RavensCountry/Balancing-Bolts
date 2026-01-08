from sqlmodel import SQLModel, create_engine, Session
import os

DATABASE_URL = f"sqlite:///{os.path.join(os.path.dirname(__file__), 'app.db')}"
engine = create_engine(DATABASE_URL, echo=False)

def init_db():
    SQLModel.metadata.create_all(engine)

def get_session():
    return Session(engine)
