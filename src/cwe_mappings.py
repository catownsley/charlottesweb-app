"""Centralized CWE to HIPAA control mappings.

This module provides shared mappings between Common Weakness Enumerations (CWE)
and HIPAA controls, reducing duplication across the codebase.
"""

# Primary CWE to Healthcare/HIPAA control mappings
CWE_TO_HIPAA_CONTROL: dict[str, str] = {
    "CWE-295": "HC.SC-7.1",  # Improper Certificate Validation → TLS/Encryption
    "CWE-311": "HC.SC-4.1",  # Missing Encryption → Data Protection
    "CWE-798": "HC.SC-2.1",  # Hard-coded Credentials → Access Control
    "CWE-347": "HC.SC-12.1",  # Improper Verification of Cryptographic Signature → Key Management
    "CWE-200": "HC.SC-7.2",  # Information Exposure → Network Security
    "CWE-778": "HC.AU-6.1",  # Insufficient Logging → Audit Logging
    "CWE-89": "HC.SC-3.1",  # SQL Injection → Input Validation
    "CWE-79": "HC.SC-3.1",  # Cross-site Scripting → Input Validation
}

# Fallback controls used when CWE mapping is unavailable or unknown.
# Ordered by preference; first existing control in DB is selected.
FALLBACK_CONTROL_CANDIDATES: list[str] = [
    "HC.SC-7.1",  # Healthcare transmission security
    "HIPAA.164.312(e)(1)",  # HIPAA transmission security
    "HIPAA.164.312(a)(2)(iv)",  # HIPAA encryption/decryption
]


def get_control_for_cwe(cwe_id: str) -> str | None:
    """Get the HIPAA control ID for a given CWE.

    Args:
        cwe_id: CWE identifier (e.g., "CWE-295")

    Returns:
        HIPAA control ID or None if not mapped
    """
    return CWE_TO_HIPAA_CONTROL.get(cwe_id)


def get_fallback_controls() -> list[str]:
    """Get list of fallback control candidates in priority order.

    Returns:
        List of control IDs to try when CWE mapping is unavailable
    """
    return FALLBACK_CONTROL_CANDIDATES.copy()
