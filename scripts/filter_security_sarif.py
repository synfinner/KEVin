#!/usr/bin/env python3
"""Prepare Codacy SARIF for GitHub's security-focused code scanning view."""

from __future__ import annotations

import argparse
import copy
import json
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any
from urllib.parse import unquote, urlparse


# Codacy reports quality and security tools in one SARIF document. GitHub's
# Code Security view should receive only tools whose primary purpose is finding
# production security defects.
SECURITY_TOOL_PREFIXES = (
    "bandit",
    "hadolint",
    "jacksonlinter",
    "opengrep",
    "semgrep",
    "trivy",
)
TEST_DIRECTORY_NAMES = frozenset({"test", "tests"})


@dataclass(frozen=True)
class FilterSummary:
    """Describe how many SARIF results were retained or removed."""

    retained_results: int = 0
    removed_test_results: int = 0
    emptied_quality_results: int = 0


def _is_security_tool(tool_name: str) -> bool:
    """Return whether a Codacy tool belongs in GitHub Code Security."""
    normalized_name = tool_name.strip().casefold()
    return normalized_name.startswith(SECURITY_TOOL_PREFIXES)


def _artifact_path(location: dict[str, Any]) -> str | None:
    """Extract and normalize a repository path from one SARIF location."""
    artifact = (
        location.get("physicalLocation", {})
        .get("artifactLocation", {})
        .get("uri")
    )
    if not isinstance(artifact, str) or not artifact:
        return None

    parsed = urlparse(artifact)
    path = parsed.path if parsed.scheme else artifact
    return unquote(path).replace("\\", "/")


def _is_test_path(path: str) -> bool:
    """Return whether a normalized path is contained in a test directory."""
    parts = PurePosixPath(path).parts
    return any(part.casefold() in TEST_DIRECTORY_NAMES for part in parts)


def _is_test_only_result(result: dict[str, Any]) -> bool:
    """Return whether every usable location for a result is test-only."""
    locations = result.get("locations")
    if not isinstance(locations, list) or not locations:
        return False

    paths = [_artifact_path(location) for location in locations]
    # Missing locations are preserved because they may represent a valid
    # repository-level finding that cannot safely be classified as test-only.
    if any(path is None for path in paths):
        return False
    return all(_is_test_path(path) for path in paths if path is not None)


def _shift_artifact_indices(value: Any, offset: int) -> None:
    """Shift artifact references recursively after two run tables are joined."""
    if isinstance(value, dict):
        artifact_location = value.get("artifactLocation")
        if isinstance(artifact_location, dict):
            artifact_index = artifact_location.get("index")
            if isinstance(artifact_index, int):
                artifact_location["index"] = artifact_index + offset
        for nested_value in value.values():
            _shift_artifact_indices(nested_value, offset)
    elif isinstance(value, list):
        for nested_value in value:
            _shift_artifact_indices(nested_value, offset)


def _merge_driver_rules(
    target_driver: dict[str, Any],
    source_driver: dict[str, Any],
) -> dict[str, int]:
    """Merge rule metadata and return each rule ID's target index."""
    target_rules = target_driver.setdefault("rules", [])
    source_rules = source_driver.get("rules", [])
    if not isinstance(target_rules, list) or not isinstance(source_rules, list):
        raise ValueError("SARIF tool driver rules must be lists.")

    rule_indices = {
        rule["id"]: index
        for index, rule in enumerate(target_rules)
        if isinstance(rule, dict) and isinstance(rule.get("id"), str)
    }
    for rule in source_rules:
        rule_id = rule.get("id") if isinstance(rule, dict) else None
        if not isinstance(rule_id, str) or rule_id in rule_indices:
            continue
        rule_indices[rule_id] = len(target_rules)
        target_rules.append(rule)
    return rule_indices


def _result_rule_id(
    result: dict[str, Any],
    source_rules: list[Any],
) -> str | None:
    """Resolve a result's rule ID from its explicit or indexed reference."""
    rule_id = result.get("ruleId")
    if isinstance(rule_id, str):
        return rule_id

    rule_reference = result.get("rule")
    if not isinstance(rule_reference, dict):
        return None
    if isinstance(rule_reference.get("id"), str):
        return rule_reference["id"]

    source_index = rule_reference.get("index")
    if not isinstance(source_index, int) or not 0 <= source_index < len(source_rules):
        return None
    source_rule = source_rules[source_index]
    if not isinstance(source_rule, dict) or not isinstance(source_rule.get("id"), str):
        return None
    return source_rule["id"]


def _merge_run(target_run: dict[str, Any], source_run: dict[str, Any]) -> None:
    """Merge one duplicate tool run into its first occurrence."""
    target_driver = target_run["tool"]["driver"]
    source_driver = source_run["tool"]["driver"]
    source_rules = source_driver.get("rules", [])
    if not isinstance(source_rules, list):
        raise ValueError("SARIF tool driver rules must be lists.")
    rule_indices = _merge_driver_rules(target_driver, source_driver)

    target_artifacts = target_run.setdefault("artifacts", [])
    source_artifacts = source_run.get("artifacts", [])
    if not isinstance(target_artifacts, list) or not isinstance(source_artifacts, list):
        raise ValueError("SARIF run artifacts must be lists.")
    artifact_offset = len(target_artifacts)
    target_artifacts.extend(source_artifacts)

    # Results from the appended run must point at the newly combined metadata
    # tables rather than retaining their original zero-based indices.
    for result in source_run["results"]:
        _shift_artifact_indices(result, artifact_offset)
        rule_id = _result_rule_id(result, source_rules)
        if rule_id in rule_indices:
            rule_reference = result.setdefault("rule", {})
            rule_reference["id"] = rule_id
            rule_reference["index"] = rule_indices[rule_id]
        target_run["results"].append(result)


def _run_category(run: dict[str, Any]) -> str:
    """Return the analysis category encoded in runAutomationDetails.id."""
    automation_id = run.get("automationDetails", {}).get("id", "")
    if not isinstance(automation_id, str) or "/" not in automation_id:
        return ""
    return automation_id.rsplit("/", 1)[0]


def _coalesce_duplicate_tool_runs(
    runs: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Return one run per tool and category while preserving input order."""
    coalesced_runs = []
    runs_by_tool = {}
    for run in runs:
        tool_name = run["tool"]["driver"]["name"]
        tool_key = (tool_name.strip().casefold(), _run_category(run))
        existing_run = runs_by_tool.get(tool_key)
        if existing_run is None:
            runs_by_tool[tool_key] = run
            coalesced_runs.append(run)
            continue
        _merge_run(existing_run, run)
    return coalesced_runs


def filter_security_sarif(
    document: dict[str, Any],
) -> tuple[dict[str, Any], FilterSummary]:
    """Return SARIF containing only production findings from security tools."""
    runs = document.get("runs")
    if not isinstance(runs, list):
        raise ValueError("SARIF document must contain a 'runs' list.")

    filtered_document = copy.deepcopy(document)
    retained_results = 0
    removed_test_results = 0
    emptied_quality_results = 0

    for run in filtered_document["runs"]:
        driver = run.get("tool", {}).get("driver", {})
        tool_name = driver.get("name", "")
        results = run.get("results", [])
        if not isinstance(tool_name, str) or not isinstance(results, list):
            raise ValueError("Each SARIF run must contain a tool name and results list.")

        if not _is_security_tool(tool_name):
            # Retaining an empty run lets GitHub supersede and close alerts
            # previously uploaded for the same quality tool.
            emptied_quality_results += len(results)
            run["results"] = []
            continue

        production_results = []
        for result in results:
            if _is_test_only_result(result):
                removed_test_results += 1
                continue
            production_results.append(result)

        run["results"] = production_results
        retained_results += len(production_results)

    filtered_document["runs"] = _coalesce_duplicate_tool_runs(
        filtered_document["runs"]
    )
    return filtered_document, FilterSummary(
        retained_results=retained_results,
        removed_test_results=removed_test_results,
        emptied_quality_results=emptied_quality_results,
    )


def filter_sarif_file(input_path: Path, output_path: Path) -> FilterSummary:
    """Read, filter, and write a SARIF document using deterministic JSON."""
    with input_path.open(encoding="utf-8") as input_file:
        document = json.load(input_file)

    filtered_document, summary = filter_security_sarif(document)
    with output_path.open("w", encoding="utf-8") as output_file:
        json.dump(filtered_document, output_file, indent=2)
        output_file.write("\n")
    return summary


def _parse_args() -> argparse.Namespace:
    """Parse command-line paths for the input and filtered SARIF documents."""
    parser = argparse.ArgumentParser(
        description="Filter Codacy SARIF for GitHub Code Security.",
    )
    parser.add_argument("input", type=Path, help="Unfiltered Codacy SARIF file")
    parser.add_argument("output", type=Path, help="Filtered SARIF output file")
    return parser.parse_args()


def main() -> int:
    """Filter one SARIF file and print a concise workflow summary."""
    args = _parse_args()
    summary = filter_sarif_file(args.input, args.output)
    print(
        "Security SARIF prepared: "
        f"{summary.retained_results} retained, "
        f"{summary.removed_test_results} test-only removed, "
        f"{summary.emptied_quality_results} quality results omitted."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
