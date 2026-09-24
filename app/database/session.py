import os
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, scoped_session
from app.core.config import get_settings

def get_engine():
    settings = get_settings()
    
    # Use an absolute path or relative to project root based on settings
    db_path = settings.database_path
    if not os.path.isabs(db_path):
        # We assume the script runs from the project root
        db_path = os.path.abspath(db_path)
        
    db_url = f"sqlite:///{db_path}"
    
    engine = create_engine(
        db_url,
        connect_args={"check_same_thread": False}, # Needed for SQLite in multi-thread
        echo=False
    )
    return engine

def get_session_factory(engine=None):
    if engine is None:
        engine = get_engine()
    return sessionmaker(autocommit=False, autoflush=False, bind=engine)

def get_db_session():
    """Dependency for getting a database session."""
    factory = get_session_factory()
    session = factory()
    try:
        yield session
    finally:
        session.close()
