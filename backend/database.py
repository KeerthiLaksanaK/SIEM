"""
database.py - SQLAlchemy database setup.
Creates the SQLite engine and session factory used across the application.
SQLite is chosen for simplicity: no separate database server is needed.
"""

import os
from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base, sessionmaker

# Store the SQLite file in the data/ directory (one level above backend/)
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, "..", "data")
os.makedirs(DATA_DIR, exist_ok=True)

DATABASE_URL = f"sqlite:///{os.path.join(DATA_DIR, 'siem.db')}"

engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False},  # Required for SQLite with FastAPI
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()


def get_db():
    """Dependency injected into FastAPI route handlers to provide a DB session."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
