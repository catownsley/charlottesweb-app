"""Control management endpoints."""
from typing import List

from fastapi import APIRouter, Depends, Request
from sqlalchemy.orm import Session

from src.config import settings
from src.database import get_db, get_or_404
from src.middleware import limiter
from src.models import Control
from src.schemas import ControlResponse

router = APIRouter(prefix="/controls", tags=["controls"])


@router.get("", response_model=list[ControlResponse])
@limiter.limit(f"{settings.rate_limit_per_minute}/minute")
def list_controls(request: Request, db: Session = Depends(get_db)) -> List[Control]:
    """List all controls."""
    controls: List[Control] = db.query(Control).all()
    return controls


@router.get("/{control_id}", response_model=ControlResponse)
@limiter.limit(f"{settings.rate_limit_per_minute}/minute")
def get_control(request: Request, control_id: str, db: Session = Depends(get_db)) -> Control:
    """Get control by ID."""
    control = get_or_404(db, Control, control_id, "Control not found")
    return control
