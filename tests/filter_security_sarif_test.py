"""Regression tests for the GitHub Code Security SARIF filter."""

from copy import deepcopy

from scripts.filter_security_sarif import filter_security_sarif


def _result(path=None, rule_id="example-rule"):
    """Build one minimal SARIF result with an optional source location."""
    result = {"ruleId": rule_id, "message": {"text": "Example finding"}}
    if path is not None:
        result["locations"] = [
            {
                "physicalLocation": {
                    "artifactLocation": {
                        "uri": path,
                    }
                }
            }
        ]
    return result


def _run(tool_name, results):
    """Build one minimal SARIF run for a named analysis tool."""
    return {
        "tool": {"driver": {"name": tool_name}},
        "results": results,
    }


def test_filter_keeps_production_security_results():
    """A production finding from a security tool remains uploadable."""
    document = {"runs": [_run("Bandit (reported by Codacy)", [_result("kevin.py")])]}

    filtered, summary = filter_security_sarif(deepcopy(document))

    assert len(filtered["runs"][0]["results"]) == 1
    assert summary.retained_results == 1
    assert summary.removed_test_results == 0


def test_filter_removes_test_only_security_results():
    """A finding located only in tests does not enter Code Security."""
    document = {
        "runs": [
            _run(
                "Bandit (reported by Codacy)",
                [_result("tests/security_regression_test.py")],
            )
        ]
    }

    filtered, summary = filter_security_sarif(deepcopy(document))

    assert filtered["runs"][0]["results"] == []
    assert summary.retained_results == 0
    assert summary.removed_test_results == 1


def test_filter_empties_quality_runs_without_dropping_them():
    """A replacement empty quality run can close its existing GitHub alerts."""
    document = {
        "runs": [
            _run("Pylintpython3 (reported by Codacy)", [_result("utils/cache.py")])
        ]
    }

    filtered, summary = filter_security_sarif(deepcopy(document))

    assert len(filtered["runs"]) == 1
    assert filtered["runs"][0]["tool"]["driver"]["name"].startswith("Pylint")
    assert filtered["runs"][0]["results"] == []
    assert summary.emptied_quality_results == 1


def test_filter_keeps_location_free_security_results():
    """A repository-level security finding is retained when it has no location."""
    document = {"runs": [_run("Trivy (reported by Codacy)", [_result()])]}

    filtered, summary = filter_security_sarif(deepcopy(document))

    assert len(filtered["runs"][0]["results"]) == 1
    assert summary.retained_results == 1


def test_filter_coalesces_duplicate_runs_from_the_same_tool():
    """One tool produces one uploadable run even when Codacy invokes it twice."""
    first_run = _run(
        "Opengrep (reported by Codacy)",
        [_result("kevin.py", rule_id="opengrep-first")],
    )
    first_run["tool"]["driver"]["rules"] = [{"id": "opengrep-first"}]
    first_run["artifacts"] = [{"location": {"uri": "kevin.py"}}]
    first_run["results"][0]["rule"] = {"id": "opengrep-first", "index": 0}
    first_run["results"][0]["locations"][0]["physicalLocation"][
        "artifactLocation"
    ]["index"] = 0

    second_run = _run(
        "Opengrep (reported by Codacy)",
        [_result("schema/api.py", rule_id="opengrep-second")],
    )
    second_run["tool"]["driver"]["rules"] = [{"id": "opengrep-second"}]
    second_run["artifacts"] = [{"location": {"uri": "schema/api.py"}}]
    second_run["results"][0]["rule"] = {"id": "opengrep-second", "index": 0}
    second_run["results"][0]["locations"][0]["physicalLocation"][
        "artifactLocation"
    ]["index"] = 0

    document = {
        "runs": [first_run, second_run]
    }

    filtered, summary = filter_security_sarif(deepcopy(document))

    assert len(filtered["runs"]) == 1
    assert [
        result["ruleId"] for result in filtered["runs"][0]["results"]
    ] == ["opengrep-first", "opengrep-second"]
    assert [
        rule["id"] for rule in filtered["runs"][0]["tool"]["driver"]["rules"]
    ] == ["opengrep-first", "opengrep-second"]
    assert [
        result["rule"]["index"] for result in filtered["runs"][0]["results"]
    ] == [0, 1]
    assert [
        result["locations"][0]["physicalLocation"]["artifactLocation"]["index"]
        for result in filtered["runs"][0]["results"]
    ] == [0, 1]
    assert summary.retained_results == 2


def test_filter_preserves_same_tool_runs_with_distinct_categories():
    """Distinct analysis categories remain independently uploadable."""
    first_run = _run(
        "Opengrep (reported by Codacy)",
        [_result("kevin.py", rule_id="opengrep-python")],
    )
    first_run["automationDetails"] = {"id": "codacy/python/"}
    second_run = _run(
        "Opengrep (reported by Codacy)",
        [_result("Dockerfile", rule_id="opengrep-docker")],
    )
    second_run["automationDetails"] = {"id": "codacy/docker/"}

    filtered, summary = filter_security_sarif(
        {"runs": [first_run, second_run]}
    )

    assert len(filtered["runs"]) == 2
    assert summary.retained_results == 2
