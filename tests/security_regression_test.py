"""Regression tests for vulnerability mitigations."""

from datetime import datetime
import importlib
from pathlib import Path
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


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


class MemoryRedis:
    """Store serialized cache values without requiring a Redis server."""

    def __init__(self):
        """Initialize an empty in-memory Redis value store."""
        self.values = {}
        self.get_calls = 0

    def get(self, key):
        """Return a cached byte payload when present."""
        self.get_calls += 1
        return self.values.get(key)

    def setex(self, key, _timeout, value):
        """Store a byte payload using the Redis setex call shape."""
        self.values[key] = value


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

        def find(self, query):
            """Record a find operation and return a controllable cursor."""
            cursor = RecordingCursor()
            self.find_calls.append(query)
            self.cursors.append(cursor)
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
            self.find_calls = []
            self.cursors = []

        def count_documents(self, query, **kwargs):
            """Record a bounded count and return no matching records."""
            self.count_calls.append((query, kwargs))
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

    assert len(kev_collection.count_calls) == 2
    assert len(kev_collection.find_calls) == 2
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
        cache_module.CacheManager(
            memory_redis,
            singleflight_wait_seconds=0.2,
        ),
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

    assert [request.value.status_code for request in requests] == [200, 200]
    assert [request.value.get_json() for request in requests] == [
        {"message": "loaded once"},
        {"message": "loaded once"},
    ]
    assert handler_calls == 1


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
            return iter(
                [
                    {
                        "_id": f"record-{index}",
                        "cveID": f"CVE-2026-{index:04d}",
                        "dateAdded": "2026-01-01",
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
    ) == 101
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
