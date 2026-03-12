"""Threat model generation service.

Synthesizes interactive threat models from assessment data by combining:
- Component metadata from MetadataProfile (software stack, infrastructure)
- Findings and CWE data from completed assessments
- MITRE ATT&CK technique mapping for real-world attack context
- STRIDE categorization for structured threat analysis

No new database tables required. Reads existing entities and computes
the model on the fly.
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime
from typing import Any

from sqlalchemy.orm import Session

from src.mitre_service import MITREService
from src.models import Assessment, Finding, MetadataProfile
from src.utils import to_str

logger = logging.getLogger(__name__)

# CWE to STRIDE category mapping
# S = Spoofing, T = Tampering, R = Repudiation,
# I = Information Disclosure, D = Denial of Service, E = Elevation of Privilege
CWE_TO_STRIDE: dict[str, list[str]] = {
    # Spoofing (authentication weaknesses)
    "CWE-287": ["Spoofing"],
    "CWE-306": ["Spoofing"],
    "CWE-308": ["Spoofing"],
    "CWE-798": ["Spoofing"],
    # Tampering (input manipulation)
    "CWE-89": ["Tampering"],
    "CWE-79": ["Tampering"],
    "CWE-352": ["Tampering"],
    # Repudiation (logging gaps)
    "CWE-778": ["Repudiation"],
    "CWE-532": ["Repudiation", "Information Disclosure"],
    # Information Disclosure (data exposure)
    "CWE-200": ["Information Disclosure"],
    "CWE-311": ["Information Disclosure"],
    "CWE-312": ["Information Disclosure"],
    "CWE-319": ["Information Disclosure"],
    "CWE-326": ["Information Disclosure"],
    "CWE-327": ["Information Disclosure"],
    "CWE-295": ["Information Disclosure"],
    # Elevation of Privilege (authorization failures)
    "CWE-285": ["Elevation of Privilege"],
    "CWE-862": ["Elevation of Privilege"],
    "CWE-261": ["Spoofing", "Elevation of Privilege"],
}

# Trust boundary definitions
TRUST_BOUNDARIES = {
    "TB1": {
        "label": "End User Environment",
        "description": "Browser and client devices",
    },
    "TB2": {
        "label": "Application Service",
        "description": "API layer, business logic, engines",
    },
    "TB3": {
        "label": "Persistence Layer",
        "description": "Databases, cloud storage, caches",
    },
    "TB4": {
        "label": "External Services",
        "description": "NVD, MITRE ATT&CK, third-party APIs",
    },
    "TB5": {
        "label": "Operational Layer",
        "description": "Logging, certificates, monitoring",
    },
}

# Keywords for assigning components to trust boundaries
_DB_KEYWORDS = (
    "postgres",
    "mysql",
    "sqlite",
    "redis",
    "mongo",
    "s3",
    "rds",
    "dynamo",
    "elastic",
    "mariadb",
    "oracle",
    "cassandra",
    "memcached",
)
_OPS_KEYWORDS = (
    "log",
    "cert",
    "tls",
    "audit",
    "monitor",
    "sentry",
    "datadog",
    "grafana",
)
_EXTERNAL_KEYWORDS = ("nvd", "mitre", "cve", "nist")


def _assign_trust_boundary(component_name: str) -> str:
    """Assign a component to a trust boundary based on name heuristics."""
    lower = component_name.lower()

    if lower in ("browser", "user", "client", "end-user"):
        return "TB1"

    if any(k in lower for k in _EXTERNAL_KEYWORDS):
        return "TB4"

    if any(k in lower for k in _OPS_KEYWORDS):
        return "TB5"

    if any(k in lower for k in _DB_KEYWORDS):
        return "TB3"

    # Default: application service layer
    return "TB2"


def _derive_nodes(
    profile: MetadataProfile,
    findings: list[Finding],
) -> list[dict[str, Any]]:
    """Derive graph nodes from metadata profile and findings."""
    nodes: list[dict[str, Any]] = []
    component_ids: set[str] = set()

    # Add trust boundary compound nodes
    for tb_id, tb_info in TRUST_BOUNDARIES.items():
        nodes.append(
            {
                "id": tb_id,
                "label": tb_info["label"],
                "type": "boundary",
                "parent": None,
                "metadata": {"description": tb_info["description"]},
            }
        )

    # Always add a user/browser node
    nodes.append(
        {
            "id": "user-browser",
            "label": "User / Browser",
            "type": "user",
            "parent": "TB1",
            "metadata": {
                "findings_count": 0,
                "max_severity": None,
                "phi_exposure": False,
            },
        }
    )
    component_ids.add("user-browser")

    # Derive component nodes from software_stack
    software_stack = getattr(profile, "software_stack", None) or {}
    phi_types = getattr(profile, "phi_types", None) or []
    has_phi = len(phi_types) > 0

    # Build a lookup: component name -> findings that reference it
    findings_by_component: dict[str, list[Finding]] = {}
    for finding in findings:
        title = to_str(getattr(finding, "title", "")).lower()
        for comp_name in software_stack:
            if comp_name.lower() in title:
                findings_by_component.setdefault(comp_name, []).append(finding)

    for comp_name, comp_info in software_stack.items():
        node_id = f"comp-{comp_name.lower().replace(' ', '-').replace('.', '-')}"
        if node_id in component_ids:
            continue
        component_ids.add(node_id)

        comp_findings = findings_by_component.get(comp_name, [])
        max_sev = None
        if comp_findings:
            severity_rank = {
                "immediate": 4,
                "critical": 4,
                "high": 3,
                "medium": 2,
                "low": 1,
            }
            max_sev = max(
                comp_findings,
                key=lambda f: severity_rank.get(
                    to_str(getattr(f, "severity", "low")).lower(), 0
                ),
            )
            max_sev = to_str(getattr(max_sev, "severity", None))

        version = ""
        if isinstance(comp_info, dict):
            version = comp_info.get("version", "")
        elif isinstance(comp_info, str):
            version = comp_info

        boundary = _assign_trust_boundary(comp_name)
        nodes.append(
            {
                "id": node_id,
                "label": comp_name,
                "type": "component",
                "parent": boundary,
                "metadata": {
                    "findings_count": len(comp_findings),
                    "max_severity": max_sev,
                    "phi_exposure": has_phi and boundary in ("TB2", "TB3"),
                    "version": version,
                },
            }
        )

    # Add cloud provider as infrastructure node
    cloud = to_str(getattr(profile, "cloud_provider", None))
    if cloud:
        cloud_id = f"infra-{cloud.lower()}"
        if cloud_id not in component_ids:
            component_ids.add(cloud_id)
            nodes.append(
                {
                    "id": cloud_id,
                    "label": f"{cloud.upper()} Cloud",
                    "type": "infrastructure",
                    "parent": "TB3",
                    "metadata": {
                        "findings_count": 0,
                        "max_severity": None,
                        "phi_exposure": has_phi,
                    },
                }
            )

    # Add external services
    for ext_id, ext_label in [("ext-nvd", "NVD API"), ("ext-mitre", "MITRE ATT&CK")]:
        if ext_id not in component_ids:
            component_ids.add(ext_id)
            nodes.append(
                {
                    "id": ext_id,
                    "label": ext_label,
                    "type": "external",
                    "parent": "TB4",
                    "metadata": {
                        "findings_count": 0,
                        "max_severity": None,
                        "phi_exposure": False,
                    },
                }
            )

    # Add application node if not already represented
    app_id = "comp-application"
    if app_id not in component_ids:
        app_findings = [
            f for f in findings if f not in sum(findings_by_component.values(), [])
        ]
        nodes.append(
            {
                "id": app_id,
                "label": "Application Service",
                "type": "component",
                "parent": "TB2",
                "metadata": {
                    "findings_count": len(app_findings),
                    "max_severity": "high" if app_findings else None,
                    "phi_exposure": has_phi,
                },
            }
        )
        component_ids.add(app_id)

    return nodes


def _derive_edges(nodes: list[dict[str, Any]], has_phi: bool) -> list[dict[str, Any]]:
    """Derive data flow edges from node topology."""
    edges: list[dict[str, Any]] = []
    edge_counter = 0

    # Get node IDs by type/boundary for connection logic
    app_nodes = [
        n["id"] for n in nodes if n["type"] == "component" and n["parent"] == "TB2"
    ]
    db_nodes = [
        n["id"]
        for n in nodes
        if n["type"] in ("component", "infrastructure") and n["parent"] == "TB3"
    ]
    ext_nodes = [n["id"] for n in nodes if n["type"] == "external"]

    # Pick a primary app node for connections
    primary_app = app_nodes[0] if app_nodes else None

    if primary_app:
        # User -> Application (HTTPS)
        edge_counter += 1
        edges.append(
            {
                "id": f"e{edge_counter}",
                "source": "user-browser",
                "target": primary_app,
                "label": "HTTPS requests",
                "data_classification": "phi" if has_phi else "internal",
                "crosses_boundary": True,
            }
        )

        # Application -> each DB/storage node
        for db_id in db_nodes:
            edge_counter += 1
            edges.append(
                {
                    "id": f"e{edge_counter}",
                    "source": primary_app,
                    "target": db_id,
                    "label": "Data read/write",
                    "data_classification": "phi" if has_phi else "internal",
                    "crosses_boundary": True,
                }
            )

        # Application -> external services
        for ext_id in ext_nodes:
            edge_counter += 1
            ext_node = next((n for n in nodes if n["id"] == ext_id), None)
            label = ext_node["label"] if ext_node else "External API"
            edges.append(
                {
                    "id": f"e{edge_counter}",
                    "source": primary_app,
                    "target": ext_id,
                    "label": f"{label} queries",
                    "data_classification": "public",
                    "crosses_boundary": True,
                }
            )

    # Connect secondary app nodes to primary
    if primary_app:
        for app_id in app_nodes[1:]:
            edge_counter += 1
            edges.append(
                {
                    "id": f"e{edge_counter}",
                    "source": primary_app,
                    "target": app_id,
                    "label": "Internal API",
                    "data_classification": "internal",
                    "crosses_boundary": False,
                }
            )

    return edges


def _generate_stride_analysis(
    findings: list[Finding],
    nodes: list[dict[str, Any]],
    mitre: MITREService,
) -> list[dict[str, Any]]:
    """Generate STRIDE threat analysis from findings and CWE mappings."""
    stride_categories: dict[str, list[dict[str, Any]]] = {
        "Spoofing": [],
        "Tampering": [],
        "Repudiation": [],
        "Information Disclosure": [],
        "Denial of Service": [],
        "Elevation of Privilege": [],
    }

    # Collect CWE IDs from all findings
    processed_cwes: set[str] = set()

    for finding in findings:
        cwe_ids = getattr(finding, "cwe_ids", None) or []
        severity = to_str(getattr(finding, "severity", "medium"))
        finding_id = to_str(getattr(finding, "id", ""))
        title = to_str(getattr(finding, "title", ""))

        for cwe_id in cwe_ids:
            if cwe_id in processed_cwes:
                continue
            processed_cwes.add(cwe_id)

            stride_cats = CWE_TO_STRIDE.get(cwe_id, [])
            if not stride_cats:
                continue

            # Get MITRE techniques for this CWE
            technique_ids = mitre.get_techniques_for_cwe(cwe_id)
            technique_names = []
            mitigations = []
            for tech_id in technique_ids[:2]:
                tech = mitre.get_technique_by_id(tech_id)
                if tech:
                    technique_names.append(f"{tech_id}: {tech['name']}")
                tech_mitigations = mitre.get_mitigations_for_technique(tech_id)
                for m in tech_mitigations[:1]:
                    mitigations.append(m.get("name", ""))

            for cat in stride_cats:
                stride_categories[cat].append(
                    {
                        "description": title,
                        "severity": severity,
                        "finding_ids": [finding_id],
                        "cwe_ids": [cwe_id],
                        "mitre_techniques": technique_names,
                        "recommended_actions": (
                            mitigations
                            if mitigations
                            else ["Review and remediate per finding guidance"]
                        ),
                    }
                )

    # If no findings map to DoS, add a generic one based on infrastructure
    if not stride_categories["Denial of Service"]:
        stride_categories["Denial of Service"].append(
            {
                "description": "Rate limiting and resource exhaustion controls should be verified",
                "severity": "medium",
                "finding_ids": [],
                "cwe_ids": [],
                "mitre_techniques": [],
                "recommended_actions": [
                    "Implement rate limiting on all public endpoints",
                    "Configure resource quotas",
                ],
            }
        )

    result = []
    for category, threats in stride_categories.items():
        result.append(
            {
                "category": category,
                "threat_count": len(threats),
                "threats": threats,
            }
        )

    return result


def generate_threat_model(
    db: Session,
    organization_id: str,
    assessment_id: str | None = None,
    mitre: MITREService | None = None,
) -> dict[str, Any]:
    """Generate a complete threat model for an organization.

    Args:
        db: Database session
        organization_id: Organization to generate for
        assessment_id: Specific assessment (uses latest completed if None)
        mitre: MITREService instance (creates one if None)

    Returns:
        Complete threat model with graph data, STRIDE analysis, and summary

    Raises:
        ValueError: If no completed assessment or metadata profile found
    """
    if mitre is None:
        mitre = MITREService()

    # Find the assessment
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

    assessment_id = to_str(getattr(assessment, "id", ""))
    profile_id = to_str(getattr(assessment, "metadata_profile_id", ""))

    # Load metadata profile
    profile = db.query(MetadataProfile).filter(MetadataProfile.id == profile_id).first()
    if not profile:
        raise ValueError("Metadata profile not found for assessment")

    # Load findings
    findings: list[Finding] = (
        db.query(Finding).filter(Finding.assessment_id == assessment_id).all()
    )

    phi_types = getattr(profile, "phi_types", None) or []
    has_phi = len(phi_types) > 0

    # Build the graph
    graph_nodes = _derive_nodes(profile, findings)
    graph_edges = _derive_edges(graph_nodes, has_phi)

    # Build STRIDE analysis
    stride_analysis = _generate_stride_analysis(findings, graph_nodes, mitre)

    # Compute summary
    component_nodes = [n for n in graph_nodes if n["type"] not in ("boundary",)]
    boundary_nodes = [n for n in graph_nodes if n["type"] == "boundary"]
    boundary_crossing_edges = [e for e in graph_edges if e.get("crosses_boundary")]
    total_stride_threats = sum(s["threat_count"] for s in stride_analysis)

    return {
        "organization_id": organization_id,
        "assessment_id": assessment_id,
        "generated_at": datetime.now(UTC).isoformat(),
        "graph": {
            "nodes": graph_nodes,
            "edges": graph_edges,
        },
        "stride_analysis": stride_analysis,
        "summary": {
            "total_components": len(component_nodes),
            "trust_boundaries": len(boundary_nodes),
            "data_flows": len(graph_edges),
            "stride_threats": total_stride_threats,
            "critical_boundary_crossings": len(boundary_crossing_edges),
            "has_phi": has_phi,
            "findings_count": len(findings),
        },
    }
