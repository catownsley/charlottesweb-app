"""Database session and engine configuration."""
from collections.abc import Generator
from typing import TypeVar

from fastapi import HTTPException
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, declarative_base, sessionmaker

from src.config import settings

# Create engine
sqlite_connect_args = {}
if "sqlite" in settings.database_url:
    sqlite_connect_args = {
        "check_same_thread": False,
        "timeout": 10,  # Wait up to 10s for database lock
        "isolation_level": None,  # Enable autocommit mode
    }

engine = create_engine(
    settings.database_url,
    connect_args=sqlite_connect_args,
    echo=settings.debug,
    pool_pre_ping=True,  # Test connection before using
)

# Session factory
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Base class for models
Base = declarative_base()

# Type variable for generic model type
T = TypeVar("T")


def get_db() -> Generator[Session, None, None]:
    """Dependency for getting database sessions."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def get_or_404[T](db: Session, model: type[T], entity_id: str, entity_name: str | None = None) -> T:
    """Get entity by ID or raise 404 HTTPException.

    Args:
        db: Database session
        model: SQLAlchemy model class
        entity_id: ID of the entity to retrieve
        entity_name: Human-readable name for error message (defaults to model tablename)

    Returns:
        Entity instance if found

    Raises:
        HTTPException: 404 if entity not found

    Example:
        >>> org = get_or_404(db, Organization, org_id)
        >>> # Instead of:
        >>> # org = db.query(Organization).filter(Organization.id == org_id).first()
        >>> # if not org:
        >>> #     raise HTTPException(status_code=404, detail="Organization not found")
    """
    entity = db.query(model).filter(model.id == entity_id).first()
    if not entity:
        name = entity_name or model.__tablename__.rstrip('s').replace('_', ' ')
        raise HTTPException(status_code=404, detail=f"{name.title()} not found")
    return entity
