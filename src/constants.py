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
