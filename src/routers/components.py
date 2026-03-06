"""Component version discovery endpoints."""
from fastapi import APIRouter, Request

from src.config import settings
from src.middleware import limiter
from src.nvd_service import NVDService

router = APIRouter(prefix="/components", tags=["components"])
nvd_service = NVDService(api_key=settings.nvd_api_key)


@router.get("/{component_name}/versions")
@limiter.limit(f"{settings.rate_limit_per_minute * 3}/minute")
def get_component_versions(request: Request, component_name: str) -> dict:
    """Get known versions of a component from NVD vulnerability data.

    Queries the National Vulnerability Database to find versions of components
    that have known CVEs. This provides dynamic version suggestions based on
    actual vulnerability records.

    Args:
        component_name: Name of the component (e.g., 'postgres', 'java', 'nodejs')

    Returns:
        Dictionary with 'versions' list of version strings found in NVD data

    Example:
        GET /api/v1/components/java/versions
        Response: {"versions": ["21", "20", "19", "18"]}
    """
    component_lower = component_name.lower().strip()

    if not component_lower or len(component_lower) < 2:
        return {"versions": []}

    # Query NVD for versions of this component
    versions = nvd_service.get_known_versions(component_lower, max_versions=10)

    return {"versions": versions}
