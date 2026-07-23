"""Regression tests for vulnerability mitigations."""

from datetime import datetime
import importlib
from pathlib import Path
import sys
import unittest
import xml.etree.ElementTree as element_tree

from flask import Flask

from utils.rss_feed import create_rss_feed


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


class MemoryRedis:
    """Store serialized cache values without requiring a Redis server."""

    def __init__(self):
        """Initialize an empty in-memory Redis value store."""
        self.values = {}

    def get(self, key):
        """Return a cached byte payload when present."""
        return self.values.get(key)

    def setex(self, key, _timeout, value):
        """Store a byte payload using the Redis setex call shape."""
        self.values[key] = value


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

    root = element_tree.fromstring(create_rss_feed([entry]))
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


def test_cached_error_tuple_preserves_http_status(monkeypatch):
    """Cached Flask error tuples retain their original HTTP status."""
    monkeypatch.setenv("REDIS_IP", "localhost")
    cache_module = importlib.import_module("utils.cache_manager")
    test_case = unittest.TestCase()

    for status_code in (400, 404):
        memory_redis = MemoryRedis()
        monkeypatch.setattr(
            cache_module,
            "cache_manager",
            cache_module.CacheManager(memory_redis),
        )

        app = Flask(__name__)
        handler_calls = 0
        route = f"/cached-error-{status_code}"

        def cached_error(response_status=status_code):
            """Return the tuple shape used by KEVin's cached error routes."""
            nonlocal handler_calls
            handler_calls += 1
            return {"message": "Vulnerability not found"}, response_status

        cached_view = cache_module.kev_cache(
            timeout=10,
            key_prefix="cached_error",
        )(cached_error)
        app.add_url_rule(
            route,
            endpoint=f"cached_error_{status_code}",
            view_func=cached_view,
            methods=["GET"],
        )

        client = app.test_client()
        first_response = client.get(route)
        cached_response = client.get(route)

        test_case.assertEqual(first_response.status_code, status_code)
        test_case.assertEqual(cached_response.status_code, status_code)
        test_case.assertEqual(cached_response.get_json(), first_response.get_json())
        test_case.assertEqual(handler_calls, 1)


def test_server_error_response_is_not_cached(monkeypatch):
    """A transient server error does not hide a recovered handler response."""
    monkeypatch.setenv("REDIS_IP", "localhost")
    cache_module = importlib.import_module("utils.cache_manager")
    memory_redis = MemoryRedis()
    monkeypatch.setattr(
        cache_module,
        "cache_manager",
        cache_module.CacheManager(memory_redis),
    )

    app = Flask(__name__)
    handler_calls = 0

    def recovering_handler():
        """Fail once, then return the healthy response clients should observe."""
        nonlocal handler_calls
        handler_calls += 1
        if handler_calls == 1:
            return {"message": "Temporary backend failure"}, 500
        return {"message": "Recovered"}, 200

    cached_view = cache_module.kev_cache(
        timeout=120,
        key_prefix="recovering_handler",
    )(recovering_handler)
    app.add_url_rule(
        "/recovering-handler",
        endpoint="recovering_handler",
        view_func=cached_view,
        methods=["GET"],
    )

    client = app.test_client()
    failed_response = client.get("/recovering-handler")
    recovered_response = client.get("/recovering-handler")
    cached_recovery_response = client.get("/recovering-handler")

    assert failed_response.status_code == 500
    assert recovered_response.status_code == 200
    assert recovered_response.get_json() == {"message": "Recovered"}
    assert cached_recovery_response.status_code == 200
    assert handler_calls == 2


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
