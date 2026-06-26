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

"""API routers for the Charlotte's Web application."""

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
    vulnerability_analysis,
)

__all__ = [
    "assessments",
    "components",
    "controls",
    "evidence",
    "findings",
    "frameworks",
    "health",
    "metadata_profiles",
    "organizations",
    "reports",
    "risk",
    "vulnerability_analysis",
]
