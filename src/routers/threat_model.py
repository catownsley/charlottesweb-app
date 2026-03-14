"""Threat model generation endpoints.

AI-powered: Claude API generates contextual threat narratives with
consolidated dependency findings, compound risk analysis, and an
AI-informed data flow diagram.

The deterministic graph-based endpoint is commented out below — it can be
re-enabled as a free-tier fallback once the product has a tiered pricing
model. See generate_threat_model() in threat_model_service.py.
"""

from __future__ import annotations

import hashlib
import json
import logging
from collections.abc import Callable
from typing import Any, TypeVar, cast

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy.orm import Session

from src.ai_threat_model_service import generate_ai_threat_model
from src.audit import AuditAction, AuditLevel, log_audit_event
from src.cache import ai_threat_model_cache
from src.config import settings
from src.database import get_db
from src.middleware import get_api_key_optional, limiter
from src.models import Assessment, Finding, MetadataProfile
from src.utils import to_str

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/threat-model", tags=["threat-model"])
F = TypeVar("F", bound=Callable[..., Any])


def _typed_get(path: str) -> Callable[[F], F]:
    return cast(Callable[[F], F], router.get(path))


def _typed_limit(rule: str) -> Callable[[F], F]:
    return cast(Callable[[F], F], limiter.limit(rule))


# ---------------------------------------------------------------------------
# Deterministic threat model endpoint (disabled)
#
# Graph-based STRIDE analysis with CWE mappings. Superseded by the AI-powered
# endpoint below which produces richer, contextual analysis with data flow
# diagrams. Kept here for potential re-use as a free-tier / no-API-key
# fallback.
#
# To re-enable:
#   1. Uncomment the endpoint and its import
#   2. Add back: from src.threat_model_service import generate_threat_model
# ---------------------------------------------------------------------------
#
# @_typed_get("/organizations/{organization_id}")
# @_typed_limit(f"{settings.rate_limit_per_minute}/minute")
# def get_threat_model(
#     request: Request,
#     organization_id: str,
#     assessment_id: str | None = Query(default=None, min_length=1),
#     db: Session = Depends(get_db),
#     api_key: str = Depends(get_api_key_optional),
# ) -> dict[str, Any]:
#     """Generate a deterministic threat model for an organization.
#
#     Returns a graph structure with components as nodes, data flows as edges,
#     trust boundaries as compound nodes, and a STRIDE threat analysis.
#
#     If assessment_id is not provided, uses the latest completed assessment.
#     """
#     try:
#         result = generate_threat_model(
#             db=db,
#             organization_id=organization_id,
#             assessment_id=assessment_id,
#         )
#     except ValueError as e:
#         raise HTTPException(status_code=404, detail=str(e)) from None
#
#     log_audit_event(
#         action=AuditAction.DATA_READ,
#         request=request,
#         api_key=api_key,
#         resource_type="threat_model",
#         level=AuditLevel.INFO,
#         details={
#             "organization_id": organization_id,
#             "assessment_id": result.get("assessment_id"),
#             "components": result.get("summary", {}).get("total_components", 0),
#             "stride_threats": result.get("summary", {}).get("stride_threats", 0),
#         },
#     )
#
#     return result


def _build_ai_cache_key(
    db: Session, organization_id: str, assessment_id: str | None
) -> str:
    """Build a cache key for AI threat model based on assessment data.

    The key is a hash of the assessment's findings and software stack,
    so the cache is automatically invalidated when data changes.
    """
    if assessment_id:
        assessment = (
            db.query(Assessment)
            .filter(
                Assessment.id == assessment_id,
                Assessment.organization_id == organization_id,
            )
            .first()
        )
    else:
        assessment = (
            db.query(Assessment)
            .filter(
                Assessment.organization_id == organization_id,
                Assessment.status == "completed",
            )
            .order_by(Assessment.initiated_at.desc())
            .first()
        )

    if not assessment:
        return f"org:{organization_id}:no-assessment"

    aid = to_str(getattr(assessment, "id", ""))
    profile_id = to_str(getattr(assessment, "metadata_profile_id", ""))
    profile = db.query(MetadataProfile).filter(MetadataProfile.id == profile_id).first()

    findings_count = db.query(Finding).filter(Finding.assessment_id == aid).count()
    stack = json.dumps(getattr(profile, "software_stack", None) or {}, sort_keys=True)

    data_hash = hashlib.sha256(
        f"{aid}:{findings_count}:{stack}:{settings.anthropic_model}".encode()
    ).hexdigest()[:16]
    return f"org:{organization_id}:assessment:{aid}:{data_hash}"


@_typed_get("/ai/organizations/{organization_id}")
@_typed_limit("10/minute")
def get_ai_threat_model(
    request: Request,
    organization_id: str,
    assessment_id: str | None = Query(default=None, min_length=1),
    force: bool = Query(default=False, description="Force regeneration, bypass cache"),
    db: Session = Depends(get_db),
    api_key: str = Depends(get_api_key_optional),
) -> dict[str, Any]:
    """Generate an AI-powered threat model for an organization.

    Uses Claude to produce a contextual threat analysis with:
    - Executive summary
    - STRIDE threat table with specific mitigations
    - Consolidated dependency finding (one entry, not per-CVE)
    - Compound risk callouts only when a CVE escalates an architectural threat
    - Prioritized remediation roadmap

    Results are cached for 7 days and automatically invalidated when
    assessment data changes. Use force=true to bypass cache.

    Requires ANTHROPIC_API_KEY to be configured.
    """
    cache_key = _build_ai_cache_key(db, organization_id, assessment_id)

    if not force:
        cached = ai_threat_model_cache.get(cache_key, db)
        if cached is not None:
            logger.info("AI threat model cache hit for org=%s", organization_id)
            cached["_cached"] = True
            return cached

    try:
        result = generate_ai_threat_model(
            db=db,
            organization_id=organization_id,
            assessment_id=assessment_id,
        )
    except ValueError as e:
        error_msg = str(e)
        if "ANTHROPIC_API_KEY" in error_msg:
            raise HTTPException(status_code=503, detail=error_msg) from None
        raise HTTPException(status_code=404, detail=error_msg) from None
    except Exception:
        logger.exception("AI threat model generation failed")
        raise HTTPException(
            status_code=500,
            detail="Threat model generation failed. Please try again.",
        ) from None

    ai_threat_model_cache.set(cache_key, result, db)
    result["_cached"] = False

    log_audit_event(
        action=AuditAction.DATA_READ,
        request=request,
        api_key=api_key,
        resource_type="ai_threat_model",
        level=AuditLevel.INFO,
        details={
            "organization_id": organization_id,
            "assessment_id": result.get("metadata", {}).get("assessment_id"),
            "stride_threats": len(result.get("stride_analysis", [])),
            "compound_risks": len(result.get("compound_risks", [])),
            "model": result.get("metadata", {}).get("model"),
        },
    )

    return result
