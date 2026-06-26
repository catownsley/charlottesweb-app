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

"""API routes for CharlottesWeb."""

from fastapi import APIRouter

from src.routers import (
    assessments,
    components,
    controls,
    evidence,
    findings,
    frameworks,
    health,
    metadata_profiles,
    organizations,
    reports,
    risk,
    threat_model,
    vulnerability_analysis,
)

router = APIRouter()

# Include all sub-routers
router.include_router(health.router)
router.include_router(components.router)
router.include_router(organizations.router)
router.include_router(metadata_profiles.router)
router.include_router(controls.router)
router.include_router(frameworks.router)
router.include_router(assessments.router)
router.include_router(findings.router)
router.include_router(reports.router)
router.include_router(vulnerability_analysis.router)
router.include_router(evidence.router)
router.include_router(risk.router)
router.include_router(threat_model.router)
