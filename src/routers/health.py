"""Health check and utility endpoints."""
from fastapi import APIRouter, Request

from src.config import settings
from src.middleware import limiter
from src.schemas import HealthResponse

__version__ = "1.0.0"

router = APIRouter(tags=["health"])


@router.get("/health", response_model=HealthResponse)
@limiter.limit(f"{settings.rate_limit_per_minute * 2}/minute")
def health_check(request: Request) -> HealthResponse:
    """Health check endpoint."""
    return HealthResponse(
        status="healthy",
        version=__version__,
        environment=settings.app_env,
    )
