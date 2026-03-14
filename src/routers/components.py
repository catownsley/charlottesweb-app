"""Component version discovery endpoints."""

from fastapi import APIRouter, HTTPException, Request

from src.config import settings
from src.manifest_parser import parse_pom_xml
from src.middleware import limiter
from src.nvd_service import NVDService
from src.schemas import (
    ManifestComponent,
    ManifestIngestRequest,
    ManifestIngestResponse,
)

router = APIRouter(prefix="/components", tags=["components"])
nvd_service = NVDService(api_key=settings.nvd_api_key)


@router.get("/suggest")
@limiter.limit(f"{settings.rate_limit_per_minute * 3}/minute")
def suggest_component_names(
    request: Request, prefix: str, limit: int = 10
) -> dict[str, list[str]]:
    """Suggest likely component names for autocomplete by prefix.

    Args:
        prefix: Component name prefix typed by the user
        limit: Maximum suggestions to return (1-20)

    Returns:
        Dictionary with a list of suggested component names
    """
    prefix_normalized = prefix.lower().strip()
    if len(prefix_normalized) < 2:
        return {"components": []}

    bounded_limit = max(1, min(limit, 20))
    suggestions = nvd_service.get_component_suggestions(
        prefix=prefix_normalized,
        max_components=bounded_limit,
    )
    return {"components": suggestions}


@router.get("/{component_name}/versions")
@limiter.limit(f"{settings.rate_limit_per_minute * 3}/minute")
def get_component_versions(
    request: Request, component_name: str, prefix: str = ""
) -> dict[str, list[str]]:
    """Get known versions of a component from NVD CPE dictionary.

    Returns versions matching an optional prefix, newest first.
    Fetches a broad set from NVD and filters server-side.

    Args:
        component_name: Name of the component (e.g., 'python', 'php')
        prefix: Optional version prefix to filter by (e.g., '3.12')

    Returns:
        Dictionary with 'versions' list (up to 10), newest first

    Example:
        GET /api/v1/components/python/versions?prefix=3.12
        Response: {"versions": ["3.12.9", "3.12.8", "3.12.7", ...]}
    """
    component_lower = component_name.lower().strip()

    if not component_lower or len(component_lower) < 2:
        return {"versions": []}

    # Fetch a large set so prefix filtering has enough to work with
    versions = nvd_service.get_known_versions(component_lower, max_versions=200)

    prefix = prefix.strip()
    if prefix:
        versions = [v for v in versions if v.startswith(prefix)]

    return {"versions": versions[:10]}


@router.post("/ingest-manifest", response_model=ManifestIngestResponse)
@limiter.limit(f"{settings.rate_limit_per_minute}/minute")
def ingest_manifest(
    request: Request, payload: ManifestIngestRequest
) -> ManifestIngestResponse:
    """Parse a supported manifest and return normalized components."""
    if payload.format != "pom_xml":
        raise HTTPException(status_code=400, detail="Unsupported manifest format")

    try:
        raw_components = parse_pom_xml(payload.content)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    # Convert dict entries to ManifestComponent instances
    components = [
        ManifestComponent(name=comp["name"], version=comp["version"])
        for comp in raw_components
    ]

    return ManifestIngestResponse(
        format=payload.format,
        components=components,
        total_components=len(components),
    )
