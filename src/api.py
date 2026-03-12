"""API routes for CharlottesWeb."""

from fastapi import APIRouter

from src.routers import (
    assessments,
    components,
    controls,
    evidence,
    findings,
    health,
    metadata_profiles,
    organizations,
    reports,
    risk,
    vulnerability_analysis,
)

router = APIRouter()

# Include all sub-routers
router.include_router(health.router)
router.include_router(components.router)
router.include_router(organizations.router)
router.include_router(metadata_profiles.router)
router.include_router(controls.router)
router.include_router(assessments.router)
router.include_router(findings.router)
router.include_router(reports.router)
router.include_router(vulnerability_analysis.router)
router.include_router(evidence.router)
router.include_router(risk.router)
