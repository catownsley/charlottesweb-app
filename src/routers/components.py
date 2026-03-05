"""Component version discovery endpoints."""
from fastapi import APIRouter, Request

from src.config import settings
from src.middleware import limiter

router = APIRouter(prefix="/components", tags=["components"])


@router.get("/{component_name}/versions")
@limiter.limit(f"{settings.rate_limit_per_minute * 3}/minute")
def get_component_versions(request: Request, component_name: str) -> dict:
    """Get known versions of a component for autocomplete suggestions.

    Returns the latest versions for popular software components.
    Users can type any version manually; actual CVE analysis searches by component name only.

    Args:
        component_name: Name of the component (e.g., 'postgres', 'java', 'nodejs')

    Returns:
        Dictionary with 'versions' list of strings (top 3 latest versions)

    Example:
        GET /api/v1/components/java/versions
        Response: {"versions": ["21", "20", "19"]}
    """
    component_lower = component_name.lower().strip()

    # Common versions for popular components (listed newest first)
    # Organized by component with realistic version strings
    known_versions = {
        'java': ['21', '20', '19', '18', '17', '16', '15', '14', '13', '12', '11', '10', '9', '8'],
        'postgres': ['16', '15', '14', '13', '12', '11', '10', '9.6', '9.5'],
        'postgresql': ['16', '15', '14', '13', '12', '11', '10', '9.6', '9.5'],
        'nodejs': ['21', '20', '19', '18', '17', '16', '15', '14', '12'],
        'node': ['21', '20', '19', '18', '17', '16', '15', '14', '12'],
        'python': ['3.13', '3.12', '3.11', '3.10', '3.9', '3.8', '3.7'],
        'nginx': ['1.26', '1.25', '1.24', '1.23', '1.22', '1.21', '1.20'],
        'mysql': ['8.3', '8.2', '8.1', '8.0', '5.7', '5.6'],
        'mongodb': ['7.0', '6.3', '6.2', '6.1', '6.0', '5.0', '4.4'],
        'redis': ['7.2', '7.1', '7.0', '6.2', '6.1', '6.0', '5.0'],
        'docker': ['25', '24', '23', '22', '21', '20', '19'],
        'openssl': ['3.2', '3.1', '3.0', '1.1.1', '1.0.2'],
    }

    # Get versions for this component, or use first few letters as fallback
    versions_to_test = known_versions.get(component_lower, [])

    if not versions_to_test:
        # Try prefix matching (e.g., "post" matches "postgres")
        for key, versions in known_versions.items():
            if key.startswith(component_lower) or component_lower.startswith(key[:3]):
                versions_to_test = versions
                break

    # If still no match but component name is provided, return empty gracefully
    if not versions_to_test:
        return {"versions": []}

    # Return top 3 latest versions for autocomplete suggestions
    # (User can type any version they want, actual NVD analysis searches by component name only)
    top_versions = versions_to_test[:3]

    return {"versions": top_versions}
