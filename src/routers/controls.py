"""Control management endpoints."""

from fastapi import APIRouter, Depends, Query, Request
from sqlalchemy.orm import Session

from src.cache import controls_cache
from src.config import settings
from src.database import get_db, get_or_404
from src.middleware import limiter
from src.models import Control
from src.pagination import PaginatedResponse
from src.schemas import ControlResponse

router = APIRouter(prefix="/controls", tags=["controls"])


@router.get("", response_model=PaginatedResponse[ControlResponse] | list[ControlResponse])
@limiter.limit(f"{settings.rate_limit_per_minute}/minute")
def list_controls(
    request: Request,
    db: Session = Depends(get_db),
    skip: int = Query(0, ge=0, description="Items to skip"),
    limit: int = Query(50, ge=1, le=1000, description="Max items (1-1000)"),
) -> PaginatedResponse[ControlResponse] | list[ControlResponse]:
    """List all controls with optional pagination.

    Query Parameters:
        skip: Number of items to skip (default: 0)
        limit: Max items to return (default: 50, max: 1000)

    Returns paginated response if limit is provided, otherwise all controls.
    Uses caching for performance (1 hour TTL).
    """
    cache_key = f"controls:all"
    cached_controls = controls_cache.get(cache_key)

    if cached_controls is not None:
        controls = cached_controls
    else:
        controls = db.query(Control).all()
        controls_cache.set(cache_key, controls)

    # Return all if limit > number of controls (for backwards compatibility)
    if limit >= len(controls):
        return controls

    total = len(controls)
    paginated = controls[skip : skip + limit]
    return PaginatedResponse.create(paginated, total, skip, limit)


@router.get("/{control_id}", response_model=ControlResponse)
@limiter.limit(f"{settings.rate_limit_per_minute}/minute")
def get_control(request: Request, control_id: str, db: Session = Depends(get_db)) -> Control:
    """Get control by ID.

    Uses cache for frequently accessed controls.
    """
    cache_key = f"control:{control_id}"
    cached_control = controls_cache.get(cache_key)

    if cached_control is not None:
        return cached_control

    control = get_or_404(db, Control, control_id, "Control not found")
    controls_cache.set(cache_key, control)
    return control
