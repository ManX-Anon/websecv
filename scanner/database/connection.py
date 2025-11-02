"""
Database connection and initialization
"""

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, scoped_session
from flask import Flask
from pathlib import Path
import os

from .models import db, Base

DATABASE_URL = os.getenv('DATABASE_URL', 'sqlite:///scanner.db')
engine = None
Session = None


def init_db(app: Flask = None, database_url: str = None):
    """Initialize database"""
    global engine, Session
    
    db_url = database_url or DATABASE_URL
    
    if app:
        # Flask-SQLAlchemy
        app.config['SQLALCHEMY_DATABASE_URI'] = db_url
        app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
        db.init_app(app)
        
        with app.app_context():
            db.create_all()
    else:
        # Standalone SQLAlchemy
        engine = create_engine(db_url, echo=False)
        Base.metadata.create_all(engine)
        Session = scoped_session(sessionmaker(bind=engine))


def get_db_session():
    """Get database session"""
    if Session:
        return Session()
    else:
        raise RuntimeError("Database not initialized. Call init_db() first.")


def close_db_session(session):
    """Close database session"""
    if session:
        session.close()

