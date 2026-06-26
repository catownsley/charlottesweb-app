# Copyright (C) 2026 Charlotte Townsley
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, version 3.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

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
