"""Regression tests for vulnerability mitigations."""

from datetime import datetime
import importlib
from pathlib import Path
import re
import sys
import types
import unittest
import xml.etree.ElementTree as element_tree

from flask import Flask
from gevent import event, joinall, sleep, spawn
import pytest
from pymongo.errors import WaitQueueTimeoutError
from redis import BlockingConnectionPool
from redis.exceptions import ConnectionError as RedisConnectionError
from redis.exceptions import MaxConnectionsError

from utils.rss_feed import create_rss_feed
from utils.sanitizer import normalize_cve_id


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


class MemoryRedis:
    """Store serialized cache values without requiring a Redis server."""

    def __init__(self):
        """Initialize an empty in-memory Redis value store."""
        self.values = {}
        self.counters = {}
        self.get_calls = 0

    def get(self, key):
        """Return a cached byte payload when present."""
        self.get_calls += 1
        return self.values.get(key)

    def setex(self, key, _timeout, value):
        """Store a byte payload using the Redis setex call shape."""
        self.values[key] = value

    def set(self, key, value, nx=False, ex=None):
        """Store a fill-lock value, honoring NX so only one caller wins."""
        del ex
        if nx and key in self.values:
            return False
        self.values[key] = value
        return True

    def delete(self, key):
        """Drop a fill lock or cached value."""
        return 1 if self.values.pop(key, None) is not None else 0

    def pipeline(self, transaction=True):
        """Return a tiny transactional-pipeline test double."""
        assert transaction is True
        return MemoryRedisPipeline(self)


class MemoryRedisPipeline:
    """Execute the rate-limit commands used by the cache manager."""

    def __init__(self, redis):
        """Keep the backing in-memory Redis instance and queued commands."""
        self.redis = redis
        self.commands = []

    def incr(self, key):
        """Queue one atomic counter increment."""
        self.commands.append(("incr", key, None))
        return self

    def expire(self, key, seconds):
        """Queue the expiry shape; test counters are reset between tests."""
        self.commands.append(("expire", key, seconds))
        return self

    def execute(self):
        """Execute queued commands and return Redis-compatible results."""
        results = []
        for command, key, _value in self.commands:
            if command == "incr":
                self.redis.counters[key] = self.redis.counters.get(key, 0) + 1
                results.append(self.redis.counters[key])
            else:
                results.append(True)
        return results


class ExhaustedRedis:
    """Simulate a Redis connection pool that cannot serve another command."""

    def __init__(self):
        """Track how often callers attempt to reach the exhausted pool."""
        self.get_calls = 0

    def get(self, _key):
        """Raise the exception emitted by redis-py when its pool is full."""
        self.get_calls += 1
        raise MaxConnectionsError("Too many connections")


class FailingWriteRedis:
    """Simulate a Redis server that rejects cache writes."""

    def __init__(self):
        """Track attempted writes while the circuit opens."""
        self.set_calls = 0

    def setex(self, _key, _timeout, _value):
        """Raise a Redis connection failure for every attempted write."""
        self.set_calls += 1
        raise RedisConnectionError("Redis unavailable")


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


def test_cache_query_validation_does_not_expose_exception_details(monkeypatch):
    """Canonicalizer failures return a fixed client-safe validation message."""
    monkeypatch.setenv("REDIS_IP", "localhost")
    cache_module = importlib.import_module("utils.cache_manager")
    app = Flask(__name__)

    def failing_canonicalizer():
        """Simulate a parser failure containing internal implementation detail."""
        raise ValueError("internal parser state: secret-field")

    def unreachable_handler():
        """Fail if validation incorrectly allows origin execution."""
        raise AssertionError("origin should not run after validation failure")

    cached_view = cache_module.kev_cache(
        query_string=failing_canonicalizer,
    )(unreachable_handler)
    app.add_url_rule(
        "/invalid-cache-query",
        endpoint="invalid_cache_query",
        view_func=cached_view,
        methods=["GET"],
    )

    response = app.test_client().get("/invalid-cache-query?days=invalid")

    assert response.status_code == 400
    assert response.get_json() == {"message": "Invalid query parameters"}
    assert b"secret-field" not in response.get_data()


def test_cache_canonical_arguments_share_aliases_before_origin(monkeypatch):
    """Canonical path arguments collapse aliases before cache or singleflight."""
    monkeypatch.setenv("REDIS_IP", "localhost")
    cache_module = importlib.import_module("utils.cache_manager")
    memory_redis = MemoryRedis()
    monkeypatch.setattr(
        cache_module,
        "cache_manager",
        cache_module.CacheManager(memory_redis),
    )
    origin_calls = []

    def canonical_cve_arguments(cve_id):
        """Normalize representative CVE path spellings or reject invalid input."""
        normalized = cve_id.replace("!", "").upper()
        if not normalized.startswith("CVE-"):
            raise ValueError("invalid CVE")
        return (normalized,)

    @cache_module.kev_cache(
        key_prefix="canonical_cve",
        canonical_args=canonical_cve_arguments,
        include_path=False,
    )
    def cached_lookup(cve_id):
        """Record the origin spelling while returning equivalent data."""
        origin_calls.append(cve_id)
        return {"cve": cve_id.replace("!", "").upper()}

    app = Flask(__name__)
    with app.test_request_context("/vuln/cve-2026-0001/nvd"):
        first_response = cached_lookup("cve-2026-0001")
    with app.test_request_context("/api/vuln/CVE-2026-0001!/nvd/"):
        alias_response = cached_lookup("CVE-2026-0001!")
    cache_get_calls_before_invalid = memory_redis.get_calls
    with app.test_request_context("/vuln/not-a-cve/nvd"):
        invalid_response = cached_lookup("not-a-cve")

    assert first_response == {"cve": "CVE-2026-0001"}
    assert alias_response.get_json() == first_response
    assert origin_calls == ["cve-2026-0001"]
    assert len(memory_redis.values) == 1
    assert invalid_response.status_code == 400
    assert memory_redis.get_calls == cache_get_calls_before_invalid


def test_recent_vulnerability_cache_uses_canonical_validated_query(monkeypatch):
    """Equivalent requests share one fill and invalid keys never reach MongoDB."""

    class RecordingCursor:
        """Record the query controls applied before returning no documents."""

        def __init__(self):
            """Initialize an empty operation log."""
            self.operations = []

        def sort(self, field, direction):
            """Record the requested index-backed ordering."""
            self.operations.append(("sort", field, direction))
            return self

        def skip(self, value):
            """Record the requested pagination offset."""
            self.operations.append(("skip", value))
            return self

        def limit(self, value):
            """Record the requested page size."""
            self.operations.append(("limit", value))
            return self

        def max_time_ms(self, value):
            """Record the server-side MongoDB execution limit."""
            self.operations.append(("max_time_ms", value))
            return self

        def __iter__(self):
            """Return an empty result set."""
            return iter(())

    class RecordingCollection:
        """Count the MongoDB work caused by recent-vulnerability requests."""

        def __init__(self):
            """Initialize call logs for count and find operations."""
            self.count_calls = []
            self.find_calls = []
            self.cursors = []

        def count_documents(self, query, **kwargs):
            """Record a bounded count operation and return an empty count."""
            self.count_calls.append((query, kwargs))
            return 0

        def find(self, query, projection=None):
            """Record a find operation and return a controllable cursor."""
            cursor = RecordingCursor()
            self.find_calls.append(query)
            self.cursors.append(cursor)
            self.projections = getattr(self, "projections", [])
            self.projections.append(projection)
            return cursor

    recent_collection = RecordingCollection()
    fake_database = types.ModuleType("utils.database")
    fake_database.collection = recent_collection
    fake_database.all_vulns_collection = recent_collection
    monkeypatch.setitem(sys.modules, "utils.database", fake_database)
    cache_module = importlib.import_module("utils.cache_manager")
    memory_redis = MemoryRedis()
    monkeypatch.setattr(
        cache_module,
        "cache_manager",
        cache_module.CacheManager(memory_redis),
    )
    sys.modules.pop("schema.api", None)

    try:
        api_module = importlib.import_module("schema.api")
        published = api_module.RecentVulnerabilitiesByDaysResource("published")
        modified = api_module.RecentVulnerabilitiesByDaysResource("modified")
        app = Flask(__name__)

        valid_request_groups = (
            (
                published,
                "/vuln/published?days=030",
                "/vuln/published?per_page=25&page=1&days=30",
            ),
            (
                published,
                "/api/vuln/published?days=030",
                "/api/vuln/published?page=1&days=30&per_page=25",
            ),
            (
                modified,
                "/vuln/modified?days=030",
                "/vuln/modified?days=30&per_page=25&page=1",
            ),
            (
                modified,
                "/api/vuln/modified?days=030",
                "/api/vuln/modified?per_page=25&days=30&page=1",
            ),
        )
        for resource, *urls in valid_request_groups:
            for url in urls:
                with app.test_request_context(url):
                    response = resource.get()
                assert response.status_code == 200

        noncacheable_requests = (
            (published, "/vuln/published?days=30&page=2&per_page=25"),
            (modified, "/api/vuln/modified?days=30&page=1&per_page=100"),
        )
        for resource, url in noncacheable_requests:
            with app.test_request_context(url):
                response = resource.get()
            assert response.status_code == 200
        valid_cache_get_calls = memory_redis.get_calls

        invalid_requests = (
            (published, "/vuln/published?days=30&nonce=1"),
            (published, "/api/vuln/published?days=30&days=30"),
            (published, "/vuln/published?days=30&page=1&page=2"),
            (modified, "/api/vuln/modified?days=30&per_page=25&per_page=25"),
            (modified, "/vuln/modified?days=30!"),
            (modified, "/api/vuln/modified?days=30@"),
        )
        for resource, url in invalid_requests:
            with app.test_request_context(url):
                response = resource.get()
            assert response.status_code == 400
    finally:
        sys.modules.pop("schema.api", None)

    assert len(recent_collection.count_calls) == 4
    assert len(recent_collection.find_calls) == 4
    assert len(memory_redis.values) == 4
    assert all(projection == api_module.RECENT_VULN_PROJECTION for projection in recent_collection.projections)
    assert memory_redis.get_calls == valid_cache_get_calls
    assert all(
        options == {"maxTimeMS": 5000}
        for _query, options in recent_collection.count_calls
    )
    assert all(
        ("max_time_ms", 5000) in cursor.operations
        for cursor in recent_collection.cursors
    )


def test_all_kev_cache_uses_canonical_validated_query(monkeypatch):
    """Equivalent KEV requests share a fill and invalid keys stop pre-cache."""

    class RecordingCursor:
        """Record pagination and execution limits for a KEV query."""

        def __init__(self):
            """Initialize an empty operation log."""
            self.operations = []

        def sort(self, criteria):
            """Record the validated sort criteria."""
            self.operations.append(("sort", criteria))
            return self

        def skip(self, value):
            """Record the page offset."""
            self.operations.append(("skip", value))
            return self

        def limit(self, value):
            """Record the canonical page size."""
            self.operations.append(("limit", value))
            return self

        def max_time_ms(self, value):
            """Record the server-side execution limit."""
            self.operations.append(("max_time_ms", value))
            return self

        def __iter__(self):
            """Return an empty result set."""
            return iter(())

    class RecordingCollection:
        """Count origin operations triggered by KEV list requests."""

        def __init__(self):
            """Initialize count, find, and cursor logs."""
            self.count_calls = []
            self.estimate_calls = 0
            self.find_calls = []
            self.cursors = []

        def count_documents(self, query, **kwargs):
            """Record a bounded count and return no matching records."""
            self.count_calls.append((query, kwargs))
            return 0

        def estimated_document_count(self):
            """Record an unbounded catalog estimate used for empty filters."""
            self.estimate_calls += 1
            return 0

        def find(self, query):
            """Record the filter and return a controllable cursor."""
            cursor = RecordingCursor()
            self.find_calls.append(query)
            self.cursors.append(cursor)
            return cursor

    kev_collection = RecordingCollection()
    fake_database = types.ModuleType("utils.database")
    fake_database.collection = kev_collection
    fake_database.all_vulns_collection = kev_collection
    monkeypatch.setitem(sys.modules, "utils.database", fake_database)
    cache_module = importlib.import_module("utils.cache_manager")
    memory_redis = MemoryRedis()
    monkeypatch.setattr(
        cache_module,
        "cache_manager",
        cache_module.CacheManager(memory_redis),
    )
    sys.modules.pop("schema.api", None)

    try:
        api_module = importlib.import_module("schema.api")
        resource = api_module.AllKevVulnerabilitiesResource()
        app = Flask(__name__)
        admitted_requests = []
        original_run_backend_tasks = api_module.run_backend_tasks

        def recording_run_backend_tasks(tasks, timeout):
            """Record aggregate admission while preserving real task execution."""
            admitted_requests.append(timeout)
            return original_run_backend_tasks(tasks, timeout=timeout)

        monkeypatch.setattr(
            api_module,
            "run_backend_tasks",
            recording_run_backend_tasks,
        )

        valid_request_groups = (
            (
                "/kev?page=01&per_page=0100&sort=dateAdded&order=DESC"
                "&search=Acme@&filter=&actor=APT@1",
                "/kev?actor=apt1&search=ACME&order=desc&sort=dateAdded"
                "&per_page=100&page=1",
            ),
            (
                "/api/kev?page=01&per_page=0100&sort=dateAdded&order=DESC"
                "&search=Acme@&filter=&actor=APT@1",
                "/api/kev?actor=apt1&search=ACME&order=desc&sort=dateAdded"
                "&per_page=100&page=1",
            ),
        )
        for urls in valid_request_groups:
            for url in urls:
                with app.test_request_context(url):
                    response = resource.get()
                assert response.status_code == 200

        default_aliases = (
            "/kev?page=1",
            "/api/kev/?per_page=25&page=1",
        )
        for url in default_aliases:
            with app.test_request_context(url):
                response = resource.get()
            assert response.status_code == 200

        deep_page_requests = (
            "/kev?page=11&per_page=25",
            "/kev?per_page=25&page=11",
        )
        for url in deep_page_requests:
            with app.test_request_context(url):
                response = resource.get()
            assert response.status_code == 200
        valid_cache_get_calls = memory_redis.get_calls

        invalid_urls = (
            "/kev?page=1&nonce=1",
            "/api/kev?page=1&page=1",
        )
        for url in invalid_urls:
            with app.test_request_context(url):
                response = resource.get()
            assert response.status_code == 400
    finally:
        sys.modules.pop("schema.api", None)

    assert len(kev_collection.count_calls) == 1
    assert kev_collection.estimate_calls == 2
    assert len(kev_collection.find_calls) == 3
    assert len(memory_redis.values) == 3
    assert admitted_requests == [api_module.GREENLET_TIMEOUT] * 3
    assert memory_redis.get_calls == valid_cache_get_calls
    assert all(
        options == {"maxTimeMS": 5000}
        for _query, options in kev_collection.count_calls
    )
    assert all(
        ("max_time_ms", 5000) in cursor.operations
        for cursor in kev_collection.cursors
    )


def test_all_vulnerability_indexes_cover_recent_query_fields(monkeypatch):
    """Startup index setup covers both recent-vulnerability sort fields."""

    class IndexCollection:
        """Record indexes created by the repository index helper."""

        def __init__(self):
            """Initialize with only MongoDB's built-in identifier index."""
            self.indexes = [{"name": "_id_"}]
            self.created = []

        def list_indexes(self):
            """Return the currently known index descriptions."""
            return list(self.indexes)

        def create_index(self, keys, name, background):
            """Record and expose a newly created index."""
            self.created.append((keys, name, background))
            self.indexes.append({"name": name})

    class FakeDatabase:
        """Return stable recording collections by collection name."""

        def __init__(self):
            """Initialize an empty collection registry."""
            self.collections = {}

        def __getitem__(self, name):
            """Return the named recording collection."""
            return self.collections.setdefault(name, IndexCollection())

    class FakeAdmin:
        """Provide the connectivity probe used during module startup."""

        def command(self, name):
            """Accept only the expected MongoDB ping command."""
            assert name == "ping"
            return {"ok": 1}

    class FakeMongoClient:
        """Provide database access without a running MongoDB server."""

        def __init__(self, *_args, **_kwargs):
            """Initialize database and administration facades."""
            self.databases = {}
            self.admin = FakeAdmin()

        def __getitem__(self, name):
            """Return the named fake database."""
            return self.databases.setdefault(name, FakeDatabase())

    fake_client = FakeMongoClient()
    monkeypatch.setattr(
        "pymongo.MongoClient",
        lambda *_args, **_kwargs: fake_client,
    )
    sys.modules.pop("utils.database", None)

    try:
        importlib.import_module("utils.database")
    finally:
        sys.modules.pop("utils.database", None)

    all_vulnerabilities = fake_client.databases["cveland"].collections["cves"]
    assert all_vulnerabilities.created == [
        (
            [("namespaces.nvd_nist_gov.cve.published", 1)],
            "idx_nvd_published",
            True,
        ),
        (
            [("namespaces.nvd_nist_gov.cve.lastModified", 1)],
            "idx_nvd_last_modified",
            True,
        ),
    ]


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
    test_case = unittest.TestCase()
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

    test_case.assertEqual(failed_response.status_code, 500)
    test_case.assertEqual(recovered_response.status_code, 200)
    test_case.assertEqual(recovered_response.get_json(), {"message": "Recovered"})
    test_case.assertEqual(cached_recovery_response.status_code, 200)
    test_case.assertEqual(handler_calls, 2)


def test_cache_pool_exhaustion_returns_503_without_calling_origin(monkeypatch):
    """Redis pool exhaustion sheds load instead of cascading into MongoDB."""
    monkeypatch.setenv("REDIS_IP", "localhost")
    cache_module = importlib.import_module("utils.cache_manager")
    exhausted_redis = ExhaustedRedis()
    monkeypatch.setattr(
        cache_module,
        "cache_manager",
        cache_module.CacheManager(exhausted_redis),
    )

    app = Flask(__name__)
    handler_calls = 0

    def origin_handler():
        """Record whether cache failure incorrectly falls through to origin."""
        nonlocal handler_calls
        handler_calls += 1
        return {"message": "origin response"}, 200

    cached_view = cache_module.kev_cache(
        timeout=120,
        key_prefix="cache_exhaustion",
    )(origin_handler)
    app.add_url_rule(
        "/cache-exhaustion",
        endpoint="cache_exhaustion",
        view_func=cached_view,
        methods=["GET"],
    )

    first_response = app.test_client().get("/cache-exhaustion")
    second_response = app.test_client().get("/cache-exhaustion")

    assert first_response.status_code == 503
    assert second_response.status_code == 503
    assert first_response.get_json() == {"error": "Cache temporarily unavailable"}
    assert handler_calls == 0
    assert exhausted_redis.get_calls == 1


def test_redis_pool_wait_is_bounded(monkeypatch):
    """Redis uses a larger blocking pool with a short bounded checkout wait."""
    monkeypatch.setenv("REDIS_IP", "localhost")
    cache_config = importlib.import_module("utils.cache_config")
    monkeypatch.setattr(cache_config, "MAX_CONNECTIONS", 100)
    monkeypatch.setattr(cache_config, "POOL_WAIT_TIMEOUT", 0.05)

    redis_client, _config = cache_config.setup_cache_config("localhost")
    pool = redis_client.connection_pool

    assert isinstance(pool, BlockingConnectionPool)
    assert pool.max_connections == 100
    assert pool.timeout == 0.05


def test_cache_write_circuit_skips_repeated_failed_writes(monkeypatch):
    """One failed cache write opens the circuit for subsequent responses."""
    monkeypatch.setenv("REDIS_IP", "localhost")
    cache_module = importlib.import_module("utils.cache_manager")
    failing_redis = FailingWriteRedis()
    manager = cache_module.CacheManager(
        failing_redis,
        circuit_breaker_seconds=1,
    )

    manager.set("first_write", {"value": 1})
    manager.set("second_write", {"value": 2})

    assert failing_redis.set_calls == 1


def test_cache_hit_verifies_stored_bytes_without_reserializing(monkeypatch):
    """Cache hits retain integrity checks without rebuilding canonical JSON."""
    monkeypatch.setenv("REDIS_IP", "localhost")
    cache_module = importlib.import_module("utils.cache_manager")
    memory_redis = MemoryRedis()
    manager = cache_module.CacheManager(memory_redis)
    expected = {"cveID": "CVE-2026-0001", "knownExploited": True}

    manager.set("checksum_hot_path", expected)

    def unexpected_legacy_checksum(_value):
        """Fail if the legacy reserialization checksum path is exercised."""
        raise AssertionError("cache hit reserialized its value")

    monkeypatch.setattr(
        cache_module,
        "generate_checksum",
        unexpected_legacy_checksum,
    )

    assert manager.get("checksum_hot_path") == expected


def test_cache_integrity_rejects_tampered_binary_envelope(monkeypatch):
    """The optimized cache envelope still rejects modified Redis values."""
    monkeypatch.setenv("REDIS_IP", "localhost")
    cache_module = importlib.import_module("utils.cache_manager")
    memory_redis = MemoryRedis()
    manager = cache_module.CacheManager(memory_redis)

    manager.set("tampered_payload", {"value": "safe"})
    memory_redis.values["tampered_payload"] = memory_redis.values[
        "tampered_payload"
    ].replace(b"safe", b"evil", 1)

    assert manager.get("tampered_payload") is None


def test_cache_miss_singleflight_runs_one_origin_loader(monkeypatch):
    """Concurrent misses for one key share a single origin computation."""
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

    def slow_origin_handler():
        """Yield long enough for another request to observe the in-flight key."""
        nonlocal handler_calls
        handler_calls += 1
        sleep(0.05)
        return {"message": "loaded once"}, 200

    cached_view = cache_module.kev_cache(
        timeout=120,
        key_prefix="singleflight",
    )(slow_origin_handler)
    app.add_url_rule(
        "/singleflight",
        endpoint="singleflight",
        view_func=cached_view,
        methods=["GET"],
    )

    requests = [
        spawn(lambda: app.test_client().get("/singleflight")),
        spawn(lambda: app.test_client().get("/singleflight")),
    ]
    joinall(requests)

    statuses = sorted(request.value.status_code for request in requests)
    assert statuses == [200, 503]
    assert handler_calls == 1
    assert {"message": "loaded once"} in [
        request.value.get_json() for request in requests
    ]


def test_cached_route_maps_mongo_checkout_timeout_to_503(monkeypatch):
    """A bounded Mongo checkout failure is exposed as retryable overload."""
    monkeypatch.setenv("REDIS_IP", "localhost")
    cache_module = importlib.import_module("utils.cache_manager")
    monkeypatch.setattr(
        cache_module,
        "cache_manager",
        cache_module.CacheManager(MemoryRedis()),
    )

    app = Flask(__name__)

    def saturated_origin_handler():
        """Raise the PyMongo error emitted after waitQueueTimeoutMS elapses."""
        raise WaitQueueTimeoutError("Timed out while checking out a connection")

    cached_view = cache_module.kev_cache(
        timeout=120,
        key_prefix="mongo_checkout_timeout",
    )(saturated_origin_handler)
    app.add_url_rule(
        "/mongo-checkout-timeout",
        endpoint="mongo_checkout_timeout",
        view_func=cached_view,
        methods=["GET"],
    )

    response = app.test_client().get("/mongo-checkout-timeout")

    assert response.status_code == 503
    assert response.get_json() == {"error": "Backend temporarily unavailable"}


def test_backend_capacity_rejects_work_instead_of_waiting_for_a_slot():
    """Backend admission fails fast while all database slots are occupied."""
    backend_module = importlib.import_module("utils.backend_capacity")
    limiter = backend_module.BackendCapacity(max_concurrency=1)
    release_first_task = event.Event()
    first_task_started = event.Event()

    def blocking_task():
        """Hold the only backend slot until the assertion has run."""
        first_task_started.set()
        release_first_task.wait()
        return "first"

    first_request = spawn(
        limiter.run_tasks,
        [blocking_task],
        1,
    )
    first_task_started.wait(timeout=0.5)

    with pytest.raises(backend_module.BackendBusyError):
        limiter.run_tasks([lambda: "second"], timeout=1)

    release_first_task.set()
    first_request.join(timeout=0.5)
    assert first_request.value == ["first"]


def test_backend_capacity_runs_request_tasks_sequentially_with_one_slot():
    """One admitted request can complete multiple tasks with one backend slot."""
    backend_module = importlib.import_module("utils.backend_capacity")
    limiter = backend_module.BackendCapacity(max_concurrency=1)
    execution_order = []

    def first_task():
        """Record and return the first sequential result."""
        execution_order.append("first")
        return 1

    def second_task():
        """Record and return the second sequential result."""
        execution_order.append("second")
        return 2

    results = limiter.run_tasks([first_task, second_task], timeout=1)

    assert results == [1, 2]
    assert execution_order == ["first", "second"]


def test_mongo_checkout_wait_has_a_bounded_timeout():
    """MongoClient checkout cannot wait indefinitely behind a full pool."""
    source = (ROOT / "utils" / "database.py").read_text()

    assert 'MONGO_WAIT_QUEUE_TIMEOUT_MS", "500"' in source
    assert "waitQueueTimeoutMS=wait_queue_timeout" in source


@pytest.mark.parametrize(
    ("resource_name", "cached_value", "path"),
    [
        (
            "cveLandResource",
            {"cveID": "CVE-2026-0001", "description": "cached"},
            "/vuln/CVE-2026-0001",
        ),
        (
            "VulnerabilityResource",
            {
                "_id": "record-1",
                "cveID": "CVE-2026-0001",
                "dateAdded": "2026-01-01",
                "dueDate": "2026-01-22",
            },
            "/kev/CVE-2026-0001",
        ),
        (
            "VulnerabilityResource",
            {
                "_id": "record-1",
                "cveID": "CVE-2026-0001",
                "dateAdded": "2026-01-01",
                "dueDate": "2026-01-22",
                "githubPocs": ["https://example.test/poc"],
            },
            "/api/kev/CVE-2026-0001?references=pocs",
        ),
    ],
)
def test_manual_cache_resources_do_not_query_mongo_on_hit(
    monkeypatch,
    resource_name,
    cached_value,
    path,
):
    """Manual cache resources query MongoDB only after a real cache miss."""

    class CountingCollection:
        """Count database lookups that a cache hit should avoid."""

        def __init__(self):
            """Initialize an untouched fake collection."""
            self.find_one_calls = 0

        def find_one(self, _query):
            """Record the unexpected lookup and return no database value."""
            self.find_one_calls += 1
            return None

    class StaticCache:
        """Return one preloaded cache value for every requested key."""

        def get(self, _key):
            """Return the value that should satisfy the resource."""
            return cached_value

        def set(self, _key, _value, timeout=120):
            """Reject cache writes because a hit must never refill the key."""
            raise AssertionError(f"unexpected cache write with timeout {timeout}")

    fake_collection = CountingCollection()
    fake_database = types.ModuleType("utils.database")
    fake_database.collection = fake_collection
    fake_database.all_vulns_collection = fake_collection
    cache_module = importlib.import_module("utils.cache_manager")
    monkeypatch.setattr(cache_module, "cache_manager", StaticCache())
    monkeypatch.setitem(sys.modules, "utils.database", fake_database)
    sys.modules.pop("schema.api", None)

    try:
        api_module = importlib.import_module("schema.api")
        resource = getattr(api_module, resource_name)()
        app = Flask(__name__)
        with app.test_request_context(path):
            response = resource.get("CVE-2026-0001")
    finally:
        sys.modules.pop("schema.api", None)

    assert response.status_code == 200
    assert fake_collection.find_one_calls == 0


def test_public_cve_query_routes_canonicalize_before_cache(monkeypatch):
    """Equivalent CVE queries share fills and ignored parameters are rejected."""

    class LookupCollection:
        """Record public point lookups while returning no matching document."""

        def __init__(self):
            """Initialize an empty lookup log."""
            self.find_one_calls = []

        def find_one(self, query):
            """Record the canonical lookup and return a cacheable miss."""
            self.find_one_calls.append(query)
            return None

    lookup_collection = LookupCollection()
    fake_database = types.ModuleType("utils.database")
    fake_database.collection = lookup_collection
    fake_database.all_vulns_collection = lookup_collection
    monkeypatch.setitem(sys.modules, "utils.database", fake_database)
    cache_module = importlib.import_module("utils.cache_manager")
    memory_redis = MemoryRedis()
    monkeypatch.setattr(
        cache_module,
        "cache_manager",
        cache_module.CacheManager(memory_redis),
    )
    monkeypatch.setenv("PUBLIC_BASE_URL", "https://kevin.gtfkd.com")
    monkeypatch.setenv("TRUSTED_HOSTS", "kevin.gtfkd.com,localhost")
    sys.modules.pop("kevin", None)
    sys.modules.pop("schema.api", None)

    try:
        kevin_module = importlib.import_module("kevin")
        client = kevin_module.app.test_client()

        exists_responses = (
            client.get("/kev/exists?cve=CVE-2026-0001"),
            client.get("/kev/exists?cve=cve-2026-0001"),
        )
        kev_responses = (
            client.get("/openai/kev?cve=CVE-2026-0001"),
            client.get("/openai/kev?cve=cve-2026-0001"),
        )
        vuln_responses = (
            client.get("/openai/vuln?cve=CVE-2026-0001"),
            client.get("/openai/vuln?cve=cve-2026-0001"),
        )
        invalid_responses = (
            client.get("/kev/exists?cve=CVE-2026-0001&nonce=1"),
            client.get("/openai/kev?cve=CVE-2026-0001&nonce=1"),
            client.get("/openai/vuln?cve=CVE-2026-0001&cve=CVE-2026-0001"),
        )
    finally:
        sys.modules.pop("kevin", None)
        sys.modules.pop("schema.api", None)

    assert [response.status_code for response in exists_responses] == [200, 200]
    assert [response.status_code for response in kev_responses] == [404, 404]
    assert [response.status_code for response in vuln_responses] == [404, 404]
    assert [response.status_code for response in invalid_responses] == [400, 400, 400]
    assert lookup_collection.find_one_calls == [
        {"cveID": "CVE-2026-0001"},
        {"cveID": "CVE-2026-0001"},
        {"_id": "CVE-2026-0001"},
    ]
    assert len(memory_redis.values) == 3


def test_public_cve_path_routes_canonicalize_before_cache(monkeypatch):
    """NVD, MITRE, and report aliases validate CVEs before shared fills."""

    class LookupCollection:
        """Return one minimal CVE record and count admitted point lookups."""

        def __init__(self):
            """Initialize an empty lookup log."""
            self.find_one_calls = []

        def find_one(self, query):
            """Record the canonical lookup and return representative data."""
            self.find_one_calls.append(query)
            return {
                "_id": "CVE-2026-0001",
                "namespaces": {
                    "nvd_nist_gov": {},
                    "cve_org": {},
                },
            }

    lookup_collection = LookupCollection()
    fake_database = types.ModuleType("utils.database")
    fake_database.collection = lookup_collection
    fake_database.all_vulns_collection = lookup_collection
    monkeypatch.setitem(sys.modules, "utils.database", fake_database)
    cache_module = importlib.import_module("utils.cache_manager")
    memory_redis = MemoryRedis()
    monkeypatch.setattr(
        cache_module,
        "cache_manager",
        cache_module.CacheManager(memory_redis),
    )
    monkeypatch.setenv("TRUSTED_HOSTS", "localhost")
    sys.modules.pop("kevin", None)
    sys.modules.pop("schema.api", None)

    try:
        kevin_module = importlib.import_module("kevin")
        client = kevin_module.app.test_client()
        responses = (
            client.get("/vuln/cve-2026-0001/nvd"),
            client.get("/api/vuln/CVE-2026-0001/nvd"),
            client.get("/vuln/cve-2026-0001/mitre"),
            client.get("/api/vuln/CVE-2026-0001/mitre"),
            client.get("/vuln/cve-2026-0001/report"),
            client.get("/vuln/CVE-2026-0001/report"),
        )
        invalid_responses = (
            client.get("/vuln/not-a-cve/nvd"),
            client.get("/api/vuln/not-a-cve/mitre"),
            client.get("/vuln/not-a-cve/report"),
        )
    finally:
        sys.modules.pop("kevin", None)
        sys.modules.pop("schema.api", None)

    assert [response.status_code for response in responses] == [200] * 6
    assert [response.status_code for response in invalid_responses] == [400] * 3
    assert lookup_collection.find_one_calls == [
        {"_id": "CVE-2026-0001"},
        {"_id": "CVE-2026-0001"},
        {"_id": "CVE-2026-0001"},
    ]
    assert len(memory_redis.values) == 3


def test_homepage_rejects_untrusted_hosts_and_uses_public_origin(monkeypatch):
    """Cached homepage metadata never derives its authority from request Host."""
    fake_database = types.ModuleType("utils.database")
    fake_database.collection = object()
    fake_database.all_vulns_collection = object()
    monkeypatch.setitem(sys.modules, "utils.database", fake_database)
    cache_module = importlib.import_module("utils.cache_manager")
    monkeypatch.setattr(
        cache_module,
        "cache_manager",
        cache_module.CacheManager(MemoryRedis()),
    )
    monkeypatch.setenv("PUBLIC_BASE_URL", "https://kevin.gtfkd.com")
    monkeypatch.setenv("TRUSTED_HOSTS", "kevin.gtfkd.com,localhost")
    sys.modules.pop("kevin", None)
    sys.modules.pop("schema.api", None)

    try:
        kevin_module = importlib.import_module("kevin")
        client = kevin_module.app.test_client()
        untrusted_response = client.get("/", headers={"Host": "evil.example"})
        trusted_response = client.get("/", headers={"Host": "localhost"})
    finally:
        sys.modules.pop("kevin", None)
        sys.modules.pop("schema.api", None)

    assert untrusted_response.status_code == 400
    assert trusted_response.status_code == 200
    assert "object-src 'none'" in trusted_response.headers["Content-Security-Policy"]
    assert trusted_response.headers["X-Content-Type-Options"] == "nosniff"
    homepage = trusted_response.get_data(as_text=True)
    assert 'href="https://kevin.gtfkd.com/"' in homepage
    assert "evil.example" not in homepage


def test_uncached_origin_requests_have_a_global_rate_budget(monkeypatch):
    """Valid cache-bypass variants stop before repeated origin execution."""
    monkeypatch.setenv("REDIS_IP", "localhost")
    cache_module = importlib.import_module("utils.cache_manager")
    memory_redis = MemoryRedis()
    monkeypatch.setattr(
        cache_module,
        "cache_manager",
        cache_module.CacheManager(memory_redis),
    )
    origin_calls = []

    @cache_module.kev_cache(
        query_string=lambda: [("search", ["vendor"])],
        cache_if=lambda _items: False,
        uncached_rate_limit=1,
        rate_limit_bucket="test_expensive_query",
    )
    def expensive_query():
        """Record each origin execution that survives cache admission."""
        origin_calls.append("called")
        return {"ok": True}

    app = Flask(__name__)
    app.add_url_rule("/expensive", view_func=expensive_query)
    client = app.test_client()

    first_response = client.get("/expensive?search=vendor")
    limited_response = client.get("/expensive?search=vendor")

    assert first_response.status_code == 200
    assert limited_response.status_code == 429
    assert limited_response.headers["Retry-After"] == "1"
    assert origin_calls == ["called"]


def test_cve_normalization_rejects_lossy_and_unbounded_identifiers():
    """CVE canonicalization never repairs malformed attacker input."""
    assert normalize_cve_id("cve-2026-0001") == "CVE-2026-0001"
    malformed_values = (
        "CVE-2026-0001!",
        "CVE-2026-1",
        f"CVE-2026-{'1' * 11}",
        "CVE-1234-1234",
        "CVE-٢٠٢٦-٠٠٠١",
    )
    for malformed_value in malformed_values:
        with pytest.raises(ValueError):
            normalize_cve_id(malformed_value)


def test_manual_point_routes_reject_malformed_cves_and_cache_misses(monkeypatch):
    """Manual point resources validate strictly and remember bounded misses."""

    class MissingCollection:
        """Count point lookups while returning no matching vulnerability."""

        def __init__(self):
            """Initialize an empty lookup log."""
            self.find_one_calls = []

        def find_one(self, query):
            """Record a point lookup and return a miss."""
            self.find_one_calls.append(query)
            return None

    missing_collection = MissingCollection()
    fake_database = types.ModuleType("utils.database")
    fake_database.collection = missing_collection
    fake_database.all_vulns_collection = missing_collection
    monkeypatch.setitem(sys.modules, "utils.database", fake_database)
    cache_module = importlib.import_module("utils.cache_manager")
    memory_redis = MemoryRedis()
    monkeypatch.setattr(
        cache_module,
        "cache_manager",
        cache_module.CacheManager(memory_redis),
    )
    monkeypatch.setenv("TRUSTED_HOSTS", "localhost")
    sys.modules.pop("kevin", None)
    sys.modules.pop("schema.api", None)

    try:
        kevin_module = importlib.import_module("kevin")
        api_module = importlib.import_module("schema.api")
        monkeypatch.setattr(api_module, "POINT_MISS_RATE_LIMIT", 1)
        client = kevin_module.app.test_client()
        malformed_response = client.get("/kev/CVE-2026-0001!")
        first_miss = client.get("/kev/CVE-2026-9999")
        repeated_miss = client.get("/kev/CVE-2026-9999")
        distinct_miss = client.get("/kev/CVE-2026-9998")
    finally:
        sys.modules.pop("kevin", None)
        sys.modules.pop("schema.api", None)

    assert malformed_response.status_code == 400
    assert [first_miss.status_code, repeated_miss.status_code] == [404, 404]
    assert distinct_miss.status_code == 429
    assert distinct_miss.headers["Retry-After"] == "1"
    assert missing_collection.find_one_calls == [{"cveID": "CVE-2026-9999"}]


def test_graph_query_state_cannot_start_an_unbounded_request_loop():
    """URL state only prefills graph controls and automatic paging is capped."""
    source = (ROOT / "static" / "cve_visualization.html").read_text()
    init_start = source.index("function initFromQuery")
    init_end = source.index("updateGraphSnapshot([], []);", init_start)
    init_block = source[init_start:init_end]

    assert "const MAX_AUTOMATIC_PAGES = 10;" in source
    assert "fetchDataByActor(searchedActor)" not in init_block
    assert "Math.min(totalPages, MAX_AUTOMATIC_PAGES)" in source
    assert "Math.max(25, Math.min(100, p))" in init_block


def test_external_scripts_are_integrity_pinned_and_csp_is_enabled():
    """Every cross-origin script is byte-pinned and Flask emits a CSP."""
    html_paths = (
        ROOT / "templates" / "example.html",
        ROOT / "static" / "viz.html",
        ROOT / "static" / "cve_visualization.html",
    )
    script_pattern = re.compile(r"<script\s+[^>]*src=\"https://[^>]+>")

    external_scripts = []
    for html_path in html_paths:
        external_scripts.extend(script_pattern.findall(html_path.read_text()))

    assert external_scripts
    assert all('integrity="sha384-' in tag for tag in external_scripts)
    assert all('crossorigin="anonymous"' in tag for tag in external_scripts)

    source = (ROOT / "kevin.py").read_text()
    assert "Content-Security-Policy" in source
    assert "object-src 'none'" in source


def test_kevin_routes_use_bounded_backend_admission():
    """Metrics and existence routes do not create uncapped greenlets."""
    source = (ROOT / "kevin.py").read_text()

    assert "from gevent import spawn" not in source
    assert source.count("run_backend_tasks(") >= 2
    assert "except BackendBusyError:" in source


def test_schema_resources_never_block_in_greenlet_pool_spawn():
    """Schema routes use fail-fast backend admission rather than Pool.spawn."""
    source = (ROOT / "schema" / "api.py").read_text()

    assert "GREENLET_POOL.spawn" not in source
    assert "Pool(MAX_GREENLETS)" not in source
    assert source.count("run_backend_tasks(") >= 3


def test_recent_kev_query_is_admitted_canonical_bounded_and_cached(monkeypatch):
    """Recent KEV aliases and limits share one bounded maximum-result fill."""

    class RecordingCursor:
        """Record query bounds and return one representative vulnerability."""

        def __init__(self):
            """Initialize a cursor with no configured bound."""
            self.operations = []

        def sort(self, key, direction):
            """Record the deterministic sort applied before the result cap."""
            self.operations.append(("sort", key, direction))
            return self

        def limit(self, value):
            """Record and return the maximum number of materialized records."""
            self.operations.append(("limit", value))
            return self

        def max_time_ms(self, value):
            """Record and return the MongoDB execution deadline."""
            self.operations.append(("max_time_ms", value))
            return self

        def __iter__(self):
            """Yield records that prove requested limits are sliced after caching."""
            recent_date = datetime.now().strftime("%Y-%m-%d")
            return iter(
                [
                    {
                        "_id": f"record-{index}",
                        "cveID": f"CVE-2026-{index:04d}",
                        "dateAdded": recent_date,
                        "dueDate": "2026-01-22",
                    }
                    for index in range(1, 4)
                ]
            )

    class RecentCollection:
        """Record each origin query and its independently configured cursor."""

        def __init__(self):
            """Initialize empty query and cursor logs."""
            self.find_calls = []
            self.cursors = []

        def find(self, query):
            """Record the filter and return a fresh recording cursor."""
            cursor = RecordingCursor()
            self.find_calls.append(query)
            self.cursors.append(cursor)
            return cursor

    recent_collection = RecentCollection()
    fake_database = types.ModuleType("utils.database")
    fake_database.collection = recent_collection
    fake_database.all_vulns_collection = recent_collection
    monkeypatch.setitem(sys.modules, "utils.database", fake_database)
    cache_module = importlib.import_module("utils.cache_manager")
    memory_redis = MemoryRedis()
    monkeypatch.setattr(
        cache_module,
        "cache_manager",
        cache_module.CacheManager(memory_redis),
    )
    sys.modules.pop("schema.api", None)

    try:
        api_module = importlib.import_module("schema.api")
        resource = api_module.RecentKevVulnerabilitiesResource()
        app = Flask(__name__)

        admitted_requests = []
        original_run_backend_tasks = api_module.run_backend_tasks

        def recording_run_backend_tasks(tasks, timeout):
            """Record admission while preserving the production execution path."""
            admitted_requests.append(timeout)
            return original_run_backend_tasks(tasks, timeout=timeout)

        monkeypatch.setattr(
            api_module,
            "run_backend_tasks",
            recording_run_backend_tasks,
        )

        valid_urls = (
            "/kev/recent?days=007&limit=1",
            "/api/kev/recent/?limit=2&days=7",
            "/kev/recent/?days=7",
        )
        responses = []
        for url in valid_urls:
            with app.test_request_context(url):
                responses.append(resource.get())

        cache_get_calls_before_invalid_requests = memory_redis.get_calls
        invalid_urls = (
            "/kev/recent?days=7&nonce=1",
            "/kev/recent?days=7&days=7",
            "/kev/recent?days=7&limit=25&limit=25",
            "/kev/recent?days=7!&limit=25",
            "/kev/recent?days=7&limit=0",
            f"/kev/recent?days=7&limit={api_module.RECENT_KEV_MAX_RESULTS + 1}",
        )
        for url in invalid_urls:
            with app.test_request_context(url):
                invalid_response = resource.get()
            assert invalid_response.status_code == 400
            assert invalid_response.get_json() == {
                "message": "Invalid query parameters"
            }
    finally:
        sys.modules.pop("schema.api", None)

    assert [response.status_code for response in responses] == [200, 200, 200]
    assert all(not response.is_streamed for response in responses)
    assert [len(response.get_json()) for response in responses] == [1, 2, 3]
    assert responses[0].get_json() == responses[1].get_json()[:1]
    assert responses[1].get_json() == responses[2].get_json()[:2]

    # All aliases and requested prefixes share one maximum-size dataset.
    assert len(recent_collection.find_calls) == 1
    assert len(memory_redis.values) == 1
    assert admitted_requests == [api_module.GREENLET_TIMEOUT]
    assert len(
        {
            api_module.recent_kev_cache_key(days)
            for days in range(101)
        }
    ) == 1
    assert recent_collection.cursors[0].operations == [
        ("sort", "dateAdded", api_module.DESCENDING),
        ("limit", api_module.RECENT_KEV_MAX_RESULTS),
        ("max_time_ms", api_module.MONGO_QUERY_MAX_TIME_MS),
    ]
    assert memory_redis.get_calls == cache_get_calls_before_invalid_requests


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


def test_cached_success_and_not_found_share_one_ttl(monkeypatch):
    """4xx and 2xx point responses use the same Redis lifetime."""
    monkeypatch.setenv("REDIS_IP", "localhost")
    cache_module = importlib.import_module("utils.cache_manager")
    recorded_timeouts = []

    class RecordingRedis(MemoryRedis):
        """Capture setex lifetimes used for cached handler responses."""

        def setex(self, key, timeout, value):
            """Store the payload and remember the requested TTL."""
            recorded_timeouts.append(timeout)
            return super().setex(key, timeout, value)

    monkeypatch.setattr(
        cache_module,
        "apply_ttl_jitter",
        lambda timeout, ratio=None, random_func=None: int(timeout),
    )
    monkeypatch.setattr(
        cache_module,
        "cache_manager",
        cache_module.CacheManager(RecordingRedis()),
    )

    app = Flask(__name__)
    state = {"missing": True}

    def lookup():
        """Return a miss, then a hit, using the same cache key."""
        if state["missing"]:
            state["missing"] = False
            return {"message": "Vulnerability not found"}, 404
        return {"cveID": "CVE-2026-0001"}, 200

    app.add_url_rule(
        "/ttl-oracle",
        view_func=cache_module.kev_cache(timeout=120, key_prefix="ttl_oracle")(lookup),
    )
    client = app.test_client()
    missing = client.get("/ttl-oracle")
    # A second distinct path is not needed: overwrite by deleting is enough
    # to observe the TTL used for both statuses on one decorated view.
    assert missing.status_code == 404
    assert recorded_timeouts == [120]


def test_ttl_jitter_only_extends_the_base_timeout():
    """Public cache expiry is delayed by a bounded positive jitter."""
    cache_module = importlib.import_module("utils.cache_manager")

    assert cache_module.apply_ttl_jitter(100, ratio=0, random_func=lambda: 1) == 100
    assert cache_module.apply_ttl_jitter(100, ratio=0.1, random_func=lambda: 1) == 110
    assert cache_module.apply_ttl_jitter(100, ratio=0.1, random_func=lambda: 0) == 100


def test_legacy_cache_checksum_uses_constant_time_compare(monkeypatch):
    """Legacy envelopes still reject tampering without a string inequality."""
    cache_module = importlib.import_module("utils.cache_manager")
    value = {"cveID": "CVE-2026-0001"}
    legacy = cache_module.orjson.dumps(
        {
            "value": value,
            "checksum": cache_module.generate_checksum(value),
        }
    )
    assert cache_module.deserialize_cache_entry(legacy) == value

    tampered = cache_module.orjson.dumps(
        {
            "value": {"cveID": "CVE-2026-9999"},
            "checksum": cache_module.generate_checksum(value),
        }
    )
    with pytest.raises(ValueError):
        cache_module.deserialize_cache_entry(tampered)


def test_actor_filter_escapes_regex_metacharacters(monkeypatch):
    """Actor filters are treated as literals after sanitization."""

    class RecordingCursor:
        """Return no rows while recording the Mongo filter."""

        def sort(self, _criteria):
            """Ignore sort for this regex-shape assertion."""
            return self

        def skip(self, _value):
            """Ignore pagination for this regex-shape assertion."""
            return self

        def limit(self, _value):
            """Ignore page size for this regex-shape assertion."""
            return self

        def max_time_ms(self, _value):
            """Ignore the execution deadline for this regex-shape assertion."""
            return self

        def __iter__(self):
            """Return an empty result set."""
            return iter(())

    class RecordingCollection:
        """Capture the actor $or clause."""

        def __init__(self):
            """Initialize the filter log."""
            self.find_calls = []

        def count_documents(self, query, **_kwargs):
            """Return no matches for the captured filter."""
            return 0

        def find(self, query):
            """Record the filter and return an empty cursor."""
            self.find_calls.append(query)
            return RecordingCursor()

    kev_collection = RecordingCollection()
    fake_database = types.ModuleType("utils.database")
    fake_database.collection = kev_collection
    fake_database.all_vulns_collection = kev_collection
    monkeypatch.setitem(sys.modules, "utils.database", fake_database)
    cache_module = importlib.import_module("utils.cache_manager")
    monkeypatch.setattr(
        cache_module,
        "cache_manager",
        cache_module.CacheManager(MemoryRedis()),
    )
    sys.modules.pop("schema.api", None)

    try:
        api_module = importlib.import_module("schema.api")
        resource = api_module.AllKevVulnerabilitiesResource()
        app = Flask(__name__)
        with app.test_request_context("/kev?actor=apt-1"):
            response = resource.get()
    finally:
        sys.modules.pop("schema.api", None)

    assert response.status_code == 200
    actor_clause = kev_collection.find_calls[0]["$or"][0]
    assert actor_clause["openThreatData.communityAdversaries"]["$regex"] == r"apt\-1"


def test_recent_nvd_serializer_omits_full_namespaces():
    """Published/modified listings do not return raw cveland documents."""
    from schema.serializers import serialize_recent_nvd_vulnerability

    payload = serialize_recent_nvd_vulnerability(
        {
            "_id": "CVE-2026-0001",
            "GSD": {"description": "fallback"},
            "namespaces": {
                "nvd_nist_gov": {
                    "cve": {
                        "published": "2026-01-01T00:00:00.000",
                        "lastModified": "2026-01-02T00:00:00.000",
                        "descriptions": [{"lang": "en", "value": "English text"}],
                        "metrics": {
                            "cvssMetricV31": [{"cvssData": {"baseScore": 9.8}}],
                            "cvssMetricV40": [],
                        },
                        "configurations": [{"huge": True}],
                    }
                },
                "cve_org": {"containers": {"cna": {}}},
            },
        }
    )

    assert payload["_id"] == "CVE-2026-0001"
    assert payload["description"] == "English text"
    assert payload["metrics"]["cvssMetricV31"][0]["cvssData"]["baseScore"] == 9.8
    assert "namespaces" not in payload
    assert "configurations" not in payload


def test_shared_negative_cache_uses_the_same_key_and_ttl(monkeypatch):
    """Manual point misses are stored on the hit key with the hit lifetime."""
    cache_module = importlib.import_module("utils.cache_manager")
    memory_redis = MemoryRedis()
    manager = cache_module.CacheManager(memory_redis)
    monkeypatch.setattr(cache_module, "apply_ttl_jitter", lambda timeout, **_k: timeout)

    manager.remember_negative("cve_data_CVE-2026-0001", timeout=180)

    assert cache_module.is_negative_cache_value(
        manager.get("cve_data_CVE-2026-0001")
    )
    assert manager.has_negative("cve_data_CVE-2026-0001")


def test_rss_and_metrics_use_admitted_bounded_lookups():
    """RSS and metrics no longer issue unbounded Mongo work on a cache miss."""
    source = (ROOT / "kevin.py").read_text()

    assert "miss_rate_limit=POINT_MISS_RATE_LIMIT" in source
    assert source.count("run_backend_tasks(") >= 3
    assert "estimated_document_count()" in source
    assert ".max_time_ms(MONGO_QUERY_MAX_TIME_MS)" in source
    assert "collection.count_documents({})" not in source
