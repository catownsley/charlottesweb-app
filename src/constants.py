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

"""Application-wide constants for Charlotte's Web."""


class AssessmentStatus:
    """Assessment status values."""

    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


class Severity:
    """Finding severity levels (ordered from most to least severe)."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"

    @classmethod
    def is_high_priority(cls, severity: str) -> bool:
        """Check if severity requires immediate attention."""
        return severity in (cls.CRITICAL, cls.HIGH)


class PriorityWindow:
    """Evidence collection priority windows."""

    IMMEDIATE = "immediate"
    THIRTY_DAYS = "30_days"
    QUARTERLY = "quarterly"
    ANNUAL = "annual"


class EvidenceStatus:
    """Evidence item completion status."""

    PENDING = "pending"
    COMPLETED = "completed"
    NOT_APPLICABLE = "not_applicable"
