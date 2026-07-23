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

    def get(self, key):
        """Return a cached byte payload when present."""
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


def test_recent_kev_stream_applies_requested_bounded_limit(monkeypatch):
    """The recent KEV cursor is capped before a streaming response begins."""

    class RecordingCursor:
        """Record cursor bounds without requiring a running MongoDB server."""

        def __init__(self):
            """Initialize a cursor with no configured bound."""
            self.limit_value = None

        def limit(self, value):
            """Record and return the maximum number of streamed records."""
            self.limit_value = value
            return self

        def batch_size(self, _value):
            """Preserve the cursor call chain used by the resource."""
            return self

        def close(self):
            """Match the PyMongo cursor cleanup interface."""

        def __iter__(self):
            """Return an empty iterator because only query shape is tested."""
            return iter(())

    class RecentCollection:
        """Return the recording cursor for a recent-vulnerability query."""

        def __init__(self):
            """Create one reusable cursor for assertion."""
            self.cursor = RecordingCursor()

        def find(self, _query):
            """Return the cursor that records the applied result cap."""
            return self.cursor

    recent_collection = RecentCollection()
    fake_database = types.ModuleType("utils.database")
    fake_database.collection = recent_collection
    fake_database.all_vulns_collection = recent_collection
    monkeypatch.setitem(sys.modules, "utils.database", fake_database)
    sys.modules.pop("schema.api", None)

    try:
        api_module = importlib.import_module("schema.api")
        resource = api_module.RecentKevVulnerabilitiesResource()
        app = Flask(__name__)
        with app.test_request_context("/kev/recent?days=100&limit=25"):
            response = resource.get.__wrapped__(resource)
    finally:
        sys.modules.pop("schema.api", None)

    assert response.status_code == 200
    assert recent_collection.cursor.limit_value == 25


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
