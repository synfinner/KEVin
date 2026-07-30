"""Regression tests for the GitHub Code Security SARIF filter."""

from copy import deepcopy

from scripts.filter_security_sarif import filter_security_sarif


def _result(path=None):
    """Build one minimal SARIF result with an optional source location."""
    result = {"ruleId": "example-rule", "message": {"text": "Example finding"}}
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
