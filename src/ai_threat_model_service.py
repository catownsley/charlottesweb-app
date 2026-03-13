"""AI-powered threat model generation using Claude API.

Transforms raw assessment data (metadata profiles, findings, software stack)
into an intelligent, contextual threat model that a security architect can
refine. Produces:

- Architectural risk analysis based on the customer's specific stack
- STRIDE threat table with specific mitigation guidance
- One consolidated dependency finding (not a line item per CVE)
- Compound risk callouts only when a specific vulnerability clearly
  escalates an architectural risk
"""

from __future__ import annotations

import json
import logging
from typing import Any

import anthropic
from sqlalchemy.orm import Session

from src.config import settings
from src.models import Assessment, Control, Finding, MetadataProfile
from src.utils import to_str

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# System prompt: defines the security architect persona and output structure
# ---------------------------------------------------------------------------

SYSTEM_PROMPT = """\
You are a senior security architect generating a threat model for a software \
system. You write clearly and precisely. Your audience is a security team that \
will use this threat model to prioritize remediation work.

RULES:
1. Analyze the ARCHITECTURE first. Identify risks inherent in the system's \
   design, data flows, and trust boundaries — independent of any specific CVE.
2. Produce a STRIDE table. Each row is an architectural threat (not a CVE). \
   Columns: Category | Threat | Affected Component | Severity | Mitigation. \
   Severity must be CRITICAL, HIGH, MEDIUM, or LOW.
3. Outdated dependencies with known CVEs/CWEs are ONE consolidated finding, \
   not a line item per vulnerability. State the number of affected components, \
   the highest severity, and the remediation (update if a fix exists; if not, \
   cite the vendor advisory). List individual CVEs only in a summary sub-table \
   within this single finding.
4. If — and ONLY if — a specific CVE clearly and demonstrably increases the \
   risk of one of the architectural threats you identified, call it out as a \
   COMPOUND RISK. Explain the causal chain (e.g., "CVE-2024-XXXX in library Y \
   allows unauthenticated access, which escalates Threat 1.2 from MEDIUM to \
   HIGH because…"). Do not force compound risks where they don't exist.
5. Do NOT include a MITRE ATT&CK column. Focus on what the team should DO, \
   not which MITRE technique an attacker might use.
6. For each mitigation, be specific and actionable. "Upgrade library X from \
   1.2.3 to 1.4.0" is good. "Review and remediate" is not.
7. Include a brief executive summary (3-5 sentences) at the top.
8. End with a prioritized remediation roadmap: what to fix first, second, third.

OUTPUT FORMAT:
Return valid JSON with this structure:
{
  "executive_summary": "string",
  "stride_analysis": [
    {
      "category": "Spoofing|Tampering|Repudiation|Information Disclosure|Denial of Service|Elevation of Privilege",
      "threat": "description of the architectural threat",
      "affected_component": "specific component or data flow",
      "severity": "CRITICAL|HIGH|MEDIUM|LOW",
      "mitigation": "specific, actionable mitigation steps"
    }
  ],
  "dependency_finding": {
    "summary": "string — overall dependency health assessment",
    "affected_count": number,
    "highest_severity": "CRITICAL|HIGH|MEDIUM|LOW",
    "remediation": "string — primary action (update, patch, workaround)",
    "details": [
      {
        "component": "name",
        "current_version": "x.y.z",
        "cve_ids": ["CVE-..."],
        "fix_available": true|false,
        "action": "specific action for this component"
      }
    ]
  },
  "compound_risks": [
    {
      "vulnerability": "CVE-ID or CWE-ID",
      "architectural_threat": "reference to STRIDE threat above",
      "escalation": "explanation of how this vulnerability worsens the threat",
      "adjusted_severity": "CRITICAL|HIGH|MEDIUM|LOW",
      "mitigation": "specific action"
    }
  ],
  "remediation_roadmap": [
    {
      "priority": 1,
      "action": "what to do",
      "rationale": "why this is first"
    }
  ]
}
"""


def _build_architecture_context(
    profile: MetadataProfile,
    findings: list[Finding],
    controls: list[Control],
) -> str:
    """Build the user message describing the customer's architecture and findings."""
    sections: list[str] = []

    # --- Organization metadata ---
    phi_types = getattr(profile, "phi_types", None) or []
    cloud = to_str(getattr(profile, "cloud_provider", None) or "not specified")
    infrastructure = getattr(profile, "infrastructure", None) or {}
    applications = getattr(profile, "applications", None) or {}
    access_controls = getattr(profile, "access_controls", None) or {}
    software_stack = getattr(profile, "software_stack", None) or {}

    sections.append("## Architecture Overview")
    sections.append(f"- Cloud provider: {cloud}")
    sections.append(f"- Handles PHI: {'yes' if phi_types else 'no'}")
    if phi_types:
        sections.append(f"- PHI types: {', '.join(str(p) for p in phi_types)}")
    if infrastructure:
        sections.append(f"- Infrastructure: {json.dumps(infrastructure, default=str)}")
    if applications:
        sections.append(f"- Applications: {json.dumps(applications, default=str)}")
    if access_controls:
        sections.append(
            f"- Access controls: {json.dumps(access_controls, default=str)}"
        )

    # --- Software stack ---
    if software_stack:
        sections.append("\n## Software Stack")
        for comp_name, comp_info in software_stack.items():
            version = ""
            if isinstance(comp_info, dict):
                version = comp_info.get("version", "unknown")
            elif isinstance(comp_info, str):
                version = comp_info
            sections.append(f"- {comp_name}: {version}")

    # --- Compliance controls ---
    if controls:
        sections.append("\n## Active Compliance Controls")
        for ctrl in controls[:20]:  # Limit to avoid token bloat
            ctrl_id = to_str(getattr(ctrl, "id", ""))
            title = to_str(getattr(ctrl, "title", ""))
            sections.append(f"- {ctrl_id}: {title}")

    # --- Assessment findings ---
    # Separate CVE findings from control-based findings
    cve_findings: list[dict[str, Any]] = []
    control_findings: list[dict[str, Any]] = []

    for f in findings:
        finding_data: dict[str, Any] = {
            "title": to_str(getattr(f, "title", "")),
            "severity": to_str(getattr(f, "severity", "medium")),
            "description": to_str(getattr(f, "description", "")),
        }

        cve_ids = getattr(f, "cve_ids", None) or []
        cwe_ids = getattr(f, "cwe_ids", None) or []
        cvss = getattr(f, "cvss_score", None)
        remediation = to_str(getattr(f, "remediation_guidance", "") or "")

        if cve_ids:
            finding_data["cve_ids"] = cve_ids
            finding_data["cwe_ids"] = cwe_ids
            if cvss is not None:
                finding_data["cvss_score"] = cvss
            if remediation:
                finding_data["remediation_guidance"] = remediation
            cve_findings.append(finding_data)
        else:
            if cwe_ids:
                finding_data["cwe_ids"] = cwe_ids
            if remediation:
                finding_data["remediation_guidance"] = remediation
            control_findings.append(finding_data)

    if control_findings:
        sections.append("\n## Compliance Findings (control gaps)")
        sections.append(json.dumps(control_findings, indent=2, default=str))

    if cve_findings:
        sections.append("\n## Vulnerability Findings (from dependency scan)")
        sections.append(json.dumps(cve_findings, indent=2, default=str))
    else:
        sections.append("\n## Vulnerability Findings")
        sections.append("No known CVEs found in current dependency scan.")

    return "\n".join(sections)


def generate_ai_threat_model(
    db: Session,
    organization_id: str,
    assessment_id: str | None = None,
) -> dict[str, Any]:
    """Generate an AI-powered threat model for an organization.

    Args:
        db: Database session
        organization_id: Organization to generate for
        assessment_id: Specific assessment (uses latest completed if None)

    Returns:
        Structured threat model with STRIDE analysis, consolidated dependency
        finding, compound risks, and remediation roadmap.

    Raises:
        ValueError: If no completed assessment, metadata profile, or API key found
    """
    if not settings.anthropic_api_key:
        raise ValueError(
            "ANTHROPIC_API_KEY is required for AI threat model generation. "
            "Set it in your environment or .env file."
        )

    # --- Load assessment ---
    if assessment_id:
        assessment = (
            db.query(Assessment)
            .filter(
                Assessment.id == assessment_id,
                Assessment.organization_id == organization_id,
            )
            .first()
        )
        if not assessment:
            raise ValueError(f"Assessment {assessment_id} not found for organization")
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
            raise ValueError("No completed assessment found for organization")

    assessment_id_str = to_str(getattr(assessment, "id", ""))
    profile_id = to_str(getattr(assessment, "metadata_profile_id", ""))

    # --- Load metadata profile ---
    profile = db.query(MetadataProfile).filter(MetadataProfile.id == profile_id).first()
    if not profile:
        raise ValueError("Metadata profile not found for assessment")

    # --- Load findings ---
    findings: list[Finding] = (
        db.query(Finding).filter(Finding.assessment_id == assessment_id_str).all()
    )

    # --- Load controls for context ---
    controls: list[Control] = db.query(Control).limit(30).all()

    # --- Build the prompt ---
    user_message = _build_architecture_context(profile, findings, controls)

    # --- Call Claude API ---
    client = anthropic.Anthropic(api_key=settings.anthropic_api_key)

    logger.info(
        "Generating AI threat model for org=%s assessment=%s",
        organization_id,
        assessment_id_str,
    )

    with client.messages.stream(
        model=settings.anthropic_model,
        max_tokens=8192,
        system=SYSTEM_PROMPT,
        messages=[{"role": "user", "content": user_message}],
        output_config={
            "format": {
                "type": "json_schema",
                "schema": _output_schema(),
            }
        },
    ) as stream:
        response = stream.get_final_message()

    # --- Parse response ---
    result_text = ""
    for block in response.content:
        if block.type == "text":
            result_text = block.text
            break

    if not result_text:
        raise ValueError("AI model returned empty response")

    try:
        threat_model: dict[str, Any] = json.loads(result_text)
    except json.JSONDecodeError as e:
        logger.error("Failed to parse AI threat model response: %s", e)
        raise ValueError("AI model returned invalid JSON") from e

    # --- Attach metadata ---
    threat_model["metadata"] = {
        "organization_id": organization_id,
        "assessment_id": assessment_id_str,
        "model": settings.anthropic_model,
        "findings_analyzed": len(findings),
        "components_analyzed": len(getattr(profile, "software_stack", None) or {}),
    }

    logger.info(
        "AI threat model generated: %d STRIDE threats, %d compound risks",
        len(threat_model.get("stride_analysis", [])),
        len(threat_model.get("compound_risks", [])),
    )

    return threat_model


def _output_schema() -> dict[str, Any]:
    """JSON schema for structured output from Claude."""
    return {
        "type": "object",
        "properties": {
            "executive_summary": {"type": "string"},
            "stride_analysis": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "category": {"type": "string"},
                        "threat": {"type": "string"},
                        "affected_component": {"type": "string"},
                        "severity": {
                            "type": "string",
                            "enum": ["CRITICAL", "HIGH", "MEDIUM", "LOW"],
                        },
                        "mitigation": {"type": "string"},
                    },
                    "required": [
                        "category",
                        "threat",
                        "affected_component",
                        "severity",
                        "mitigation",
                    ],
                    "additionalProperties": False,
                },
            },
            "dependency_finding": {
                "type": "object",
                "properties": {
                    "summary": {"type": "string"},
                    "affected_count": {"type": "integer"},
                    "highest_severity": {
                        "type": "string",
                        "enum": ["CRITICAL", "HIGH", "MEDIUM", "LOW"],
                    },
                    "remediation": {"type": "string"},
                    "details": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "properties": {
                                "component": {"type": "string"},
                                "current_version": {"type": "string"},
                                "cve_ids": {
                                    "type": "array",
                                    "items": {"type": "string"},
                                },
                                "fix_available": {"type": "boolean"},
                                "action": {"type": "string"},
                            },
                            "required": [
                                "component",
                                "current_version",
                                "cve_ids",
                                "fix_available",
                                "action",
                            ],
                            "additionalProperties": False,
                        },
                    },
                },
                "required": [
                    "summary",
                    "affected_count",
                    "highest_severity",
                    "remediation",
                    "details",
                ],
                "additionalProperties": False,
            },
            "compound_risks": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "vulnerability": {"type": "string"},
                        "architectural_threat": {"type": "string"},
                        "escalation": {"type": "string"},
                        "adjusted_severity": {
                            "type": "string",
                            "enum": ["CRITICAL", "HIGH", "MEDIUM", "LOW"],
                        },
                        "mitigation": {"type": "string"},
                    },
                    "required": [
                        "vulnerability",
                        "architectural_threat",
                        "escalation",
                        "adjusted_severity",
                        "mitigation",
                    ],
                    "additionalProperties": False,
                },
            },
            "remediation_roadmap": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "priority": {"type": "integer"},
                        "action": {"type": "string"},
                        "rationale": {"type": "string"},
                    },
                    "required": ["priority", "action", "rationale"],
                    "additionalProperties": False,
                },
            },
        },
        "required": [
            "executive_summary",
            "stride_analysis",
            "dependency_finding",
            "compound_risks",
            "remediation_roadmap",
        ],
        "additionalProperties": False,
    }
