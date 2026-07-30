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
