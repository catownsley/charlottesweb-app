"""Threat model generation endpoint.

Generates interactive threat models from assessment data, combining component
metadata, MITRE ATT&CK techniques, and STRIDE analysis into a visualization-ready
graph structure.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any, TypeVar, cast

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy.orm import Session

from src.audit import AuditAction, AuditLevel, log_audit_event
from src.config import settings
from src.database import get_db
from src.middleware import get_api_key_optional, limiter
from src.threat_model_service import generate_threat_model

router = APIRouter(prefix="/threat-model", tags=["threat-model"])
F = TypeVar("F", bound=Callable[..., Any])


def _typed_get(path: str) -> Callable[[F], F]:
    return cast(Callable[[F], F], router.get(path))


def _typed_limit(rule: str) -> Callable[[F], F]:
    return cast(Callable[[F], F], limiter.limit(rule))


@_typed_get("/organizations/{organization_id}")
@_typed_limit(f"{settings.rate_limit_per_minute}/minute")
def get_threat_model(
    request: Request,
    organization_id: str,
    assessment_id: str | None = Query(default=None, min_length=1),
    db: Session = Depends(get_db),
    api_key: str = Depends(get_api_key_optional),
) -> dict[str, Any]:
    """Generate a threat model for an organization.

    Returns a graph structure with components as nodes, data flows as edges,
    trust boundaries as compound nodes, and a STRIDE threat analysis.

    If assessment_id is not provided, uses the latest completed assessment.
    """
    try:
        result = generate_threat_model(
            db=db,
            organization_id=organization_id,
            assessment_id=assessment_id,
        )
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))

    log_audit_event(
        action=AuditAction.DATA_READ,
        request=request,
        api_key=api_key,
        resource_type="threat_model",
        level=AuditLevel.INFO,
        details={
            "organization_id": organization_id,
            "assessment_id": result.get("assessment_id"),
            "components": result.get("summary", {}).get("total_components", 0),
            "stride_threats": result.get("summary", {}).get("stride_threats", 0),
        },
    )

    return result
