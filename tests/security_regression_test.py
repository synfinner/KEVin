"""Regression tests for vulnerability mitigations."""

from datetime import datetime
import importlib
from pathlib import Path
import sys
import xml.etree.ElementTree as ET

from utils.rss_feed import create_rss_feed


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


def test_rss_feed_escapes_description_html_fields():
    """RSS descriptions escape attacker-controlled HTML fragments."""
    entry = {
        "cveID": "CVE-2026-0001",
        "vulnerabilityName": "Name",
        "dateAdded": datetime(2026, 1, 1),
        "shortDescription": "<b>escaped</b>",
        "knownRansomwareCampaignUse": "<img src=x onerror=alert(1)>",
        "githubPocs": ["<img src=x onerror=alert(2)>"],
        "openThreatData": [
            {
                "adversaries": ["<img src=x onerror=alert(3)>"],
                "affectedIndustries": ["<img src=x onerror=alert(4)>"],
            }
        ],
    }

    root = ET.fromstring(create_rss_feed([entry]))
    description = root.find("channel/item/description").text

    assert "<img" not in description
    assert "&lt;img src=x onerror=alert(1)&gt;" in description
    assert "&lt;img src=x onerror=alert(2)&gt;" in description
    assert "&lt;img src=x onerror=alert(3)&gt;" in description
    assert "&lt;img src=x onerror=alert(4)&gt;" in description


def test_cache_keys_include_function_identity_and_path(monkeypatch):
    """Redis cache keys separate route and function identity."""
    monkeypatch.setenv("REDIS_IP", "localhost")
    cache_manager = importlib.import_module("utils.cache_manager")

    cve = ("CVE-2026-0001",)
    nvd_key = cache_manager.build_cache_key(
        "cache_",
        "schema.api.cveNVDResource.get",
        {"method_args": cve, "path": "/vuln/CVE-2026-0001/nvd"},
    )
    mitre_key = cache_manager.build_cache_key(
        "cache_",
        "schema.api.cveMitreResource.get",
        {"method_args": cve, "path": "/vuln/CVE-2026-0001/mitre"},
    )
    assert nvd_key != mitre_key

    query_items = [("days", ["7"]), ("page", ["1"]), ("per_page", ["25"])]
    published_key = cache_manager.build_cache_key(
        "recent_days_vulnerabilities",
        "schema.api.RecentVulnerabilitiesByDaysResource.get",
        {"query_items": query_items, "path": "/vuln/published"},
    )
    modified_key = cache_manager.build_cache_key(
        "recent_days_vulnerabilities",
        "schema.api.RecentVulnerabilitiesByDaysResource.get",
        {"query_items": query_items, "path": "/vuln/modified"},
    )
    assert published_key != modified_key


def test_viz_uses_text_safe_rendering_for_untrusted_api_data():
    """Visualization code avoids unsafe HTML sinks for untrusted API fields."""
    source = (ROOT / "static" / "viz.html").read_text()

    assert "function escapeHtml(value)" in source
    assert "{ data: 'cveId', render: textRenderer }" in source
    assert "{ data: 'description', className: 'description', render: textRenderer }" in source
    assert "$('#modalContent').html" not in source
    assert "$('#modalContent').empty().append($card)" in source
    assert "data.githubPocs.filter(isHttpUrl)" in source


def test_public_pagination_paths_validate_page_before_skip():
    """Public pagination paths validate page values before MongoDB skip calls."""
    source = (ROOT / "schema" / "api.py").read_text()

    assert "MAX_PAGE" in source
    assert source.count("page = validate_page(page)") >= 2
    assert "skip((page - 1) * per_page)" in source
