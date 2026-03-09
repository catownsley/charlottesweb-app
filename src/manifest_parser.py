"""Manifest parsing utilities for software stack ingestion."""

from __future__ import annotations

from collections import defaultdict
from xml.etree import ElementTree as ET


def _local_name(tag: str) -> str:
    if "}" in tag:
        return tag.split("}", 1)[1]
    return tag


def _find_child_text(node: ET.Element, child_name: str) -> str | None:
    for child in list(node):
        if _local_name(child.tag) == child_name and child.text:
            value = child.text.strip()
            if value:
                return value
    return None


def _resolve_property(value: str | None, properties: dict[str, str]) -> str | None:
    if value is None:
        return None

    candidate = value.strip()
    if candidate.startswith("${") and candidate.endswith("}"):
        prop_name = candidate[2:-1].strip()
        resolved = properties.get(prop_name)
        return resolved.strip() if resolved else None
    return candidate


def parse_pom_xml(content: str) -> list[dict[str, str]]:  # noqa: C901
    """Parse Maven pom.xml content into component/version pairs.

    Returns a deterministic, de-duplicated list sorted by component name.
    """
    try:
        root = ET.fromstring(content)
    except ET.ParseError as exc:
        raise ValueError("Invalid XML format for pom.xml") from exc

    properties: dict[str, str] = {}
    managed_versions: dict[tuple[str, str], str] = {}

    for node in root.iter():
        if _local_name(node.tag) != "properties":
            continue
        for prop in list(node):
            if prop.text and prop.tag:
                key = _local_name(prop.tag).strip()
                value = prop.text.strip()
                if key and value:
                    properties[key] = value

    for node in root.iter():
        if _local_name(node.tag) != "dependencyManagement":
            continue
        for dep in node.iter():
            if _local_name(dep.tag) != "dependency":
                continue
            group_id = _resolve_property(_find_child_text(dep, "groupId"), properties)
            artifact_id = _resolve_property(
                _find_child_text(dep, "artifactId"), properties
            )
            version = _resolve_property(_find_child_text(dep, "version"), properties)
            if group_id and artifact_id and version:
                managed_versions[(group_id, artifact_id)] = version

    by_name: dict[str, str] = {}
    duplicates: dict[str, int] = defaultdict(int)

    for dep in root.iter():
        if _local_name(dep.tag) != "dependency":
            continue

        artifact_id = _resolve_property(_find_child_text(dep, "artifactId"), properties)
        group_id = _resolve_property(_find_child_text(dep, "groupId"), properties)
        version = _resolve_property(_find_child_text(dep, "version"), properties)

        if not version and group_id and artifact_id:
            version = managed_versions.get((group_id, artifact_id))

        if not artifact_id or not version:
            continue

        name = artifact_id.lower().strip()
        if not name:
            continue

        if name in by_name and by_name[name] != version:
            duplicates[name] += 1
            name = f"{name}_{duplicates[name] + 1}"

        by_name[name] = version

    components = [{"name": name, "version": by_name[name]} for name in sorted(by_name)]

    if not components:
        raise ValueError(
            "No dependencies with explicit or managed versions were found in pom.xml"
        )

    return components
