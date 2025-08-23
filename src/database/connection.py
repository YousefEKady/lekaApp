#!/usr/bin/env python3
"""
Database Connection Module - Leka-App SaaS Edition

Handles PostgreSQL database connections, session management,
and database initialization for the SaaS platform.

Author: Yousef
Project: Leka-App SaaS Edition
"""

import logging
from typing import Generator, Optional
from contextlib import contextmanager

from sqlalchemy import create_engine, event, text
from sqlalchemy.engine import Engine
from sqlalchemy.orm import sessionmaker, Session
from sqlalchemy.pool import StaticPool

try:
    from src.config.config import config
except ImportError:
    # Fallback configuration
    class Config:
        DATABASE_URL = "postgresql://postgres:postgres123@localhost:5432/leka_app"
        DATABASE_ECHO = False
        DATABASE_POOL_SIZE = 10
        DATABASE_MAX_OVERFLOW = 20
        DATABASE_POOL_TIMEOUT = 30
        DATABASE_POOL_RECYCLE = 3600
        
        def get_postgres_url(self, async_mode: bool = False) -> str:
            """Get PostgreSQL connection URL."""
            return self.DATABASE_URL
    config = Config()

# Import models separately to avoid circular imports
try:
    from src.database.models import Base, create_tables
except ImportError:
    Base = None
    create_tables = None

logger = logging.getLogger(__name__)


class DatabaseManager:
    """Database connection and session manager."""
    
    def __init__(self):
        self.engine: Optional[Engine] = None
        self.SessionLocal: Optional[sessionmaker] = None
        self._initialized = False
    
    def initialize(self, database_url: Optional[str] = None) -> None:
        """Initialize database connection and session factory."""
        if self._initialized:
            logger.warning("Database already initialized")
            return
        
        try:
            # Use provided URL or fallback to config
            db_url = database_url or config.get_postgres_url(async_mode=False)
            
            # Engine configuration
            engine_kwargs = {
                'echo': getattr(config, 'DATABASE_ECHO', False),
                'pool_size': 10,
                'max_overflow': 20,
                'pool_timeout': 30,
                'pool_recycle': getattr(config, 'DATABASE_POOL_RECYCLE', 3600),
                'pool_pre_ping': True,  # Verify connections before use
            }
            
            # Handle SQLite for testing
            if db_url.startswith('sqlite'):
                engine_kwargs = {
                    'echo': getattr(config, 'DATABASE_ECHO', False),
                    'poolclass': StaticPool,
                    'connect_args': {'check_same_thread': False}
                }
            
            self.engine = create_engine(db_url, **engine_kwargs)
            
            # Add connection event listeners
            self._setup_event_listeners()
            
            # Create session factory
            self.SessionLocal = sessionmaker(
                autocommit=False,
                autoflush=False,
                bind=self.engine
            )
            
            self._initialized = True
            logger.info(f"Database initialized successfully: {db_url.split('@')[-1] if '@' in db_url else db_url}")
            
        except Exception as e:
            logger.error(f"Failed to initialize database: {e}")
            raise
    
    def _setup_event_listeners(self) -> None:
        """Setup database event listeners for monitoring and optimization."""
        
        @event.listens_for(self.engine, "connect")
        def set_sqlite_pragma(dbapi_connection, connection_record):
            """Set SQLite pragmas for better performance (if using SQLite)."""
            if 'sqlite' in str(self.engine.url):
                cursor = dbapi_connection.cursor()
                cursor.execute("PRAGMA foreign_keys=ON")
                cursor.execute("PRAGMA journal_mode=WAL")
                cursor.execute("PRAGMA synchronous=NORMAL")
                cursor.execute("PRAGMA cache_size=10000")
                cursor.execute("PRAGMA temp_store=MEMORY")
                cursor.close()
        
        @event.listens_for(self.engine, "before_cursor_execute")
        def receive_before_cursor_execute(conn, cursor, statement, parameters, context, executemany):
            """Log slow queries for performance monitoring."""
            context._query_start_time = logger.info
        
        @event.listens_for(self.engine, "after_cursor_execute")
        def receive_after_cursor_execute(conn, cursor, statement, parameters, context, executemany):
            """Log query execution time."""
            # This is a placeholder for query performance monitoring
            # In production, you might want to log slow queries
            pass
    
    def create_tables(self) -> None:
        """Create all database tables."""
        if not self._initialized:
            raise RuntimeError("Database not initialized")
        
        try:
            if Base and create_tables:
                create_tables(self.engine)
            else:
                logger.warning("Database models not available for table creation")
        except Exception as e:
            logger.error(f"Failed to create tables: {e}")
            raise
    
    def get_session(self) -> Session:
        """Get a new database session."""
        if not self._initialized or not self.SessionLocal:
            raise RuntimeError("Database not initialized")
        
        return self.SessionLocal()
    
    @contextmanager
    def get_session_context(self) -> Generator[Session, None, None]:
        """Get a database session with automatic cleanup."""
        session = self.get_session()
        try:
            yield session
            session.commit()
        except Exception as e:
            session.rollback()
            logger.error(f"Database session error: {e}")
            raise
        finally:
            session.close()
    
    def test_connection(self) -> bool:
        """Test database connection."""
        if not self._initialized:
            return False
        
        try:
            with self.engine.connect() as connection:
                connection.execute(text("SELECT 1"))
            logger.info("Database connection test successful")
            return True
        except Exception as e:
            logger.error(f"Database connection test failed: {e}")
            return False
    
    def close(self) -> None:
        """Close database connections."""
        if self.engine:
            self.engine.dispose()
            logger.info("Database connections closed")
        self._initialized = False


# Global database manager instance
db_manager = DatabaseManager()


# Dependency function for FastAPI
def get_db() -> Generator[Session, None, None]:
    """FastAPI dependency to get database session."""
    if not db_manager._initialized:
        raise RuntimeError("Database not initialized")
    
    session = db_manager.get_session()
    try:
        yield session
    finally:
        session.close()


# Utility functions
def init_database(database_url: Optional[str] = None, create_tables_flag: bool = True) -> None:
    """Initialize database with optional table creation."""
    try:
        db_manager.initialize(database_url)
        
        if create_tables_flag:
            db_manager.create_tables()
        
        # Test connection
        if not db_manager.test_connection():
            raise RuntimeError("Database connection test failed")
        
        logger.info("Database initialization completed successfully")
        
    except Exception as e:
        logger.error(f"Database initialization failed: {e}")
        raise


def close_database() -> None:
    """Close database connections."""
    db_manager.close()


# Database health check
def health_check() -> dict:
    """Perform database health check."""
    try:
        if not db_manager._initialized:
            return {
                "status": "error",
                "message": "Database not initialized"
            }
        
        # Test connection
        connection_ok = db_manager.test_connection()
        
        if connection_ok:
            return {
                "status": "healthy",
                "message": "Database connection is working",
                "database_url": str(db_manager.engine.url).split('@')[-1] if '@' in str(db_manager.engine.url) else str(db_manager.engine.url)
            }
        else:
            return {
                "status": "error",
                "message": "Database connection failed"
            }
    
    except Exception as e:
        logger.error(f"Database health check failed: {e}")
        return {
            "status": "error",
            "message": f"Health check failed: {str(e)}"
        }