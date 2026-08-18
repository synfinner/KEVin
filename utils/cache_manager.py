"""Redis cache helpers for KEVin API responses."""

from collections import OrderedDict
from contextlib import contextmanager
from datetime import datetime
import functools
import hashlib
import hmac
import logging
import os
import re
import secrets
import threading
import time

import orjson
from bson import ObjectId
from flask import Response, has_request_context, make_response, request
from gevent.lock import Semaphore
from pymongo.errors import PyMongoError
from redis.exceptions import RedisError

from utils.cache_config import redis_client


# Regular expression for safe cache keys
SAFE_KEY_RE = re.compile(r"^[\w\-:]+$")
CACHE_ENVELOPE_PREFIX = b"kevin-cache-v2:"
logger = logging.getLogger(__name__)
RATE_LIMIT_WINDOW_SECONDS = max(
    1,
    int(os.getenv("ORIGIN_RATE_LIMIT_WINDOW_SECONDS", "1")),
)
UNCACHED_QUERY_RATE_LIMIT = max(
    1,
    int(os.getenv("UNCACHED_QUERY_RATE_LIMIT", "10")),
)
POINT_MISS_RATE_LIMIT = max(
    1,
    int(os.getenv("POINT_MISS_RATE_LIMIT", "20")),
)
NEGATIVE_CACHE_TIMEOUT = max(
    1,
    int(os.getenv("NEGATIVE_CACHE_TIMEOUT", "15")),
)
NEGATIVE_CACHE_MAX_ENTRIES = max(
    1,
    int(os.getenv("NEGATIVE_CACHE_MAX_ENTRIES", "1024")),
)
POINT_MISS_RATE_BUCKET = "cve_point_miss"
# Default minimum entropy for tokens and lock owners (16 bytes).
SECURE_RANDOM_BYTES = 16
NEGATIVE_CACHE_MARKER = {"kevin_negative": True}
FILL_LOCK_SECONDS = max(
    1,
    int(os.getenv("CACHE_FILL_LOCK_SECONDS", "15")),
)
CACHE_TTL_JITTER_RATIO = max(
    0.0,
    float(os.getenv("CACHE_TTL_JITTER_RATIO", "0.1")),
)
LOCAL_REPEAT_CACHE_MAX_ENTRIES = max(
    1,
    int(os.getenv("LOCAL_REPEAT_CACHE_MAX_ENTRIES", "64")),
)
LOCAL_REPEAT_CACHE_TTL = max(
    1,
    int(os.getenv("LOCAL_REPEAT_CACHE_TTL", "30")),
)
FILL_LOCK_RELEASE_SCRIPT = """
if redis.call("get", KEYS[1]) == ARGV[1] then
    return redis.call("del", KEYS[1])
end
return 0
"""


class CacheBackendUnavailable(RuntimeError):
    """Signal that Redis is unavailable and origin load must be shed."""


class OriginRateLimitExceeded(RuntimeError):
    """Signal that a shared origin-work budget has been exhausted."""


def is_negative_cache_value(value):
    """Return whether a cache payload represents a shared, stored miss."""
    return isinstance(value, dict) and value.get("kevin_negative") is True


def apply_ttl_jitter(timeout, key=None, ratio=None, rng=None):
    """Add a CSPRNG-bounded positive spread to a cache TTL."""
    del key
    timeout = max(1, int(timeout))
    jitter_ratio = (
        CACHE_TTL_JITTER_RATIO if ratio is None else max(0.0, float(ratio))
    )
    if jitter_ratio <= 0:
        return timeout
    spread = max(1, int(timeout * jitter_ratio))
    sample = secrets.randbelow if rng is None else rng
    return timeout + int(sample(spread + 1))


class _SingleflightEntry:
    """Track one keyed fill lock and every request currently referencing it."""

    def __init__(self):
        """Create an unlocked fill slot with no registered users."""
        self.lock = Semaphore(1)
        self.users = 0


def sanitize_cache_key(key):
    """Ensure cache keys are safe and valid."""
    if not SAFE_KEY_RE.match(key):
        raise ValueError(f"Unsafe cache key: {key}")
    return key

def hash_cache_component(value):
    """Hash arbitrary cache-key material into a safe fixed-width component."""
    return hashlib.sha256(str(value).encode("utf-8")).hexdigest()

def normalize_cache_key_prefix(prefix_value):
    """Return a safe cache-key prefix, hashing caller values with unsafe characters."""
    if prefix_value is None:
        prefix_value = "cache"
    else:
        prefix_value = str(prefix_value)

    if not SAFE_KEY_RE.match(prefix_value):
        prefix_value = hash_cache_component(prefix_value)

    return prefix_value

def build_cache_key(prefix_value, func_identity, cache_context=None):
    """Build a route-aware cache key for cached Flask handlers."""
    cache_context = cache_context or {}
    method_args = cache_context.get("method_args")
    kwargs = cache_context.get("kwargs")
    query_items = cache_context.get("query_items")
    path = cache_context.get("path")

    key_parts = [
        normalize_cache_key_prefix(prefix_value),
        f"func_{hash_cache_component(func_identity)}",
    ]

    if path:
        key_parts.append(f"path_{hash_cache_component(path)}")

    if method_args:
        args_hash = hashlib.sha256(
            orjson.dumps(make_orjson_safe(method_args), option=orjson.OPT_SORT_KEYS)
        ).hexdigest()
        key_parts.append(f"args_{args_hash}")

    if kwargs:
        kwargs_hash = hashlib.sha256(
            orjson.dumps(
                make_orjson_safe(dict(sorted(kwargs.items()))),
                option=orjson.OPT_SORT_KEYS,
            )
        ).hexdigest()
        key_parts.append(f"kwargs_{kwargs_hash}")

    if query_items is not None:
        query_params = str(sorted(query_items))
        query_hash = hashlib.sha256(query_params.encode('utf-8')).hexdigest()
        key_parts.append(f"query_{query_hash}")

    return sanitize_cache_key("_".join(key_parts))

def make_orjson_safe(obj):
    """
    Recursively convert ObjectId and datetime to str/isoformat for orjson compatibility.
    """
    if isinstance(obj, dict):
        return {k: make_orjson_safe(v) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [make_orjson_safe(i) for i in obj]
    elif isinstance(obj, ObjectId):
        return str(obj)
    elif isinstance(obj, datetime):
        return obj.isoformat()
    else:
        return obj

def generate_checksum(data):
    """
    Generate a checksum for the given data using orjson for serialization.
    Ensures consistent, canonical output for hashing.
    """
    if isinstance(data, str):
        data_bytes = data.encode("utf-8")
    else:
        safe_data = make_orjson_safe(data)
        data_bytes = orjson.dumps(safe_data, option=orjson.OPT_SORT_KEYS)
    return hashlib.sha256(data_bytes).hexdigest()


def serialize_cache_entry(value):
    """Serialize one integrity-protected value without duplicating its JSON."""
    safe_value = make_orjson_safe(value)
    value_bytes = orjson.dumps(safe_value, option=orjson.OPT_SORT_KEYS)
    checksum = hashlib.sha256(value_bytes).hexdigest().encode("ascii")
    return CACHE_ENVELOPE_PREFIX + checksum + b":" + value_bytes


def deserialize_cache_entry(cached_data):
    """Verify and decode current or legacy cache payloads."""
    if cached_data.startswith(CACHE_ENVELOPE_PREFIX):
        envelope = cached_data[len(CACHE_ENVELOPE_PREFIX):]
        stored_checksum, separator, value_bytes = envelope.partition(b":")
        if not separator:
            raise ValueError("Cache envelope is missing its value separator.")

        generated_checksum = hashlib.sha256(value_bytes).hexdigest().encode("ascii")
        if not hmac.compare_digest(generated_checksum, stored_checksum):
            raise ValueError("Cache integrity check failed.")
        return orjson.loads(value_bytes)

    # Legacy entries remain readable during rolling deployments and naturally
    # disappear when their existing TTL expires.
    legacy_entry = orjson.loads(cached_data)
    value = legacy_entry.get("value")
    stored_checksum = legacy_entry.get("checksum")
    generated_checksum = generate_checksum(value)
    if not isinstance(stored_checksum, str) or not hmac.compare_digest(
        generated_checksum,
        stored_checksum,
    ):
        raise ValueError("Cache integrity check failed.")
    return value


class CacheManager:
    def __init__(
        self,
        redis_connection,
        circuit_breaker_seconds=None,
        singleflight_wait_seconds=None,
        time_func=None,
        wall_time_func=None,
        negative_cache_ttl=None,
        negative_cache_max_entries=None,
    ):
        """Initialize bounded Redis admission and local negative caching."""
        self.redis_client = redis_connection
        self.circuit_breaker_seconds = (
            float(os.getenv("CACHE_CIRCUIT_BREAKER_SECONDS", "1"))
            if circuit_breaker_seconds is None
            else max(0.0, float(circuit_breaker_seconds))
        )
        self.singleflight_wait_seconds = (
            float(os.getenv("CACHE_SINGLEFLIGHT_WAIT_SECONDS", "0"))
            if singleflight_wait_seconds is None
            else max(0.0, float(singleflight_wait_seconds))
        )
        self.fill_lock_seconds = FILL_LOCK_SECONDS
        self._time = time.monotonic if time_func is None else time_func
        self._wall_time = time.time if wall_time_func is None else wall_time_func
        self._unavailable_until = 0.0
        self._singleflight_entries = {}
        self._singleflight_guard = threading.Lock()
        self.negative_cache_ttl = (
            NEGATIVE_CACHE_TIMEOUT
            if negative_cache_ttl is None
            else max(0.0, float(negative_cache_ttl))
        )
        self.negative_cache_max_entries = (
            NEGATIVE_CACHE_MAX_ENTRIES
            if negative_cache_max_entries is None
            else max(1, int(negative_cache_max_entries))
        )
        self._negative_entries = OrderedDict()
        self._negative_guard = threading.Lock()
        self.local_repeat_ttl = LOCAL_REPEAT_CACHE_TTL
        self.local_repeat_max_entries = LOCAL_REPEAT_CACHE_MAX_ENTRIES
        self._local_repeat_entries = OrderedDict()
        self._local_repeat_guard = threading.Lock()

    def _ensure_backend_available(self):
        """Fail fast while the Redis failure circuit remains open."""
        if self._time() < self._unavailable_until:
            raise CacheBackendUnavailable("Redis failure circuit is open")

    def _mark_backend_unavailable(self):
        """Open the Redis failure circuit for the configured cooldown."""
        self._unavailable_until = self._time() + self.circuit_breaker_seconds

    def _mark_backend_available(self):
        """Close the Redis failure circuit after a successful command."""
        self._unavailable_until = 0.0

    def _fill_lock_key(self, key):
        """Return the Redis lock key that serializes one origin fill."""
        return sanitize_cache_key(f"fill_{normalize_cache_key_prefix(key)}")

    def _acquire_fill_lock(self, key):
        """Acquire a cluster-wide fill lock or fail closed if Redis is down."""
        self._ensure_backend_available()
        lock_key = self._fill_lock_key(key)
        owner = secrets.token_hex(SECURE_RANDOM_BYTES)
        try:
            acquired = self.redis_client.set(
                lock_key,
                owner,
                nx=True,
                ex=self.fill_lock_seconds,
            )
        except RedisError as exc:
            self._mark_backend_unavailable()
            raise CacheBackendUnavailable("Redis fill lock failed") from exc
        self._mark_backend_available()
        return owner if acquired else None

    def _release_fill_lock(self, key, owner):
        """Delete the fill lock only when this caller still owns it."""
        if not owner:
            return
        try:
            self._ensure_backend_available()
            self.redis_client.eval(
                FILL_LOCK_RELEASE_SCRIPT,
                1,
                self._fill_lock_key(key),
                owner,
            )
            self._mark_backend_available()
        except (RedisError, CacheBackendUnavailable):
            return

    @contextmanager
    def singleflight(self, key, wait_seconds=None, use_redis_lock=True):
        """Yield whether this request acquired the local and Redis fill slots."""
        with self._singleflight_guard:
            entry = self._singleflight_entries.get(key)
            if entry is None:
                entry = _SingleflightEntry()
                self._singleflight_entries[key] = entry
            entry.users += 1

        wait_timeout = (
            self.singleflight_wait_seconds
            if wait_seconds is None
            else max(0.0, float(wait_seconds))
        )
        acquired = entry.lock.acquire(timeout=wait_timeout)
        lock_owner = None
        try:
            if acquired and use_redis_lock:
                lock_owner = self._acquire_fill_lock(key)
                yield lock_owner is not None
            else:
                yield acquired
        finally:
            if lock_owner is not None:
                self._release_fill_lock(key, lock_owner)
            if acquired:
                entry.lock.release()
            with self._singleflight_guard:
                entry.users -= 1
                if entry.users == 0:
                    self._singleflight_entries.pop(key, None)

    def enforce_rate_limit(self, bucket, limit, window_seconds=None):
        """Atomically admit one unit of origin work in a shared Redis window."""
        if limit is None:
            return

        self._ensure_backend_available()
        window = max(
            1,
            int(
                RATE_LIMIT_WINDOW_SECONDS
                if window_seconds is None
                else window_seconds
            ),
        )
        window_id = int(self._wall_time() // window)
        safe_bucket = normalize_cache_key_prefix(bucket)
        counter_key = sanitize_cache_key(
            f"origin_rate_{safe_bucket}_{window_id}"
        )
        try:
            pipeline = self.redis_client.pipeline(transaction=True)
            pipeline.incr(counter_key)
            pipeline.expire(counter_key, window * 2)
            count, _ = pipeline.execute()
        except RedisError as exc:
            self._mark_backend_unavailable()
            raise CacheBackendUnavailable("Redis admission check failed") from exc

        self._mark_backend_available()
        if int(count) > max(1, int(limit)):
            raise OriginRateLimitExceeded(
                f"Origin rate limit exceeded for {safe_bucket}"
            )

    def has_negative(self, key):
        """Return whether a shared or local miss entry remains active."""
        safe_key = sanitize_cache_key(key)
        now = self._time()
        with self._negative_guard:
            self._prune_negative_entries(now)
            expires_at = self._negative_entries.get(safe_key)
            if expires_at is not None and expires_at > now:
                self._negative_entries.move_to_end(safe_key)
                return True
            self._negative_entries.pop(safe_key, None)

        try:
            return is_negative_cache_value(self.get(safe_key))
        except CacheBackendUnavailable:
            return False

    def remember_negative(self, key, timeout=None):
        """Remember one miss in Redis and a bounded local LRU."""
        ttl = (
            self.negative_cache_ttl
            if timeout is None
            else max(1, int(timeout))
        )
        if ttl <= 0:
            return

        safe_key = sanitize_cache_key(key)
        now = self._time()
        with self._negative_guard:
            self._prune_negative_entries(now)
            self._negative_entries[safe_key] = now + ttl
            self._negative_entries.move_to_end(safe_key)
            while len(self._negative_entries) > self.negative_cache_max_entries:
                self._negative_entries.popitem(last=False)
        self.set(safe_key, NEGATIVE_CACHE_MARKER, timeout=ttl)

    def get_local_repeat(self, key):
        """Return a bounded in-process repeat of an uncached origin response."""
        safe_key = sanitize_cache_key(key)
        now = self._time()
        with self._local_repeat_guard:
            expires_at = self._local_repeat_entries.get(safe_key)
            if expires_at is None:
                return None
            expires, value = expires_at
            if expires <= now:
                self._local_repeat_entries.pop(safe_key, None)
                return None
            self._local_repeat_entries.move_to_end(safe_key)
            return value

    def remember_local_repeat(self, key, value, timeout=None):
        """Remember one uncached response without writing a Redis key."""
        ttl = self.local_repeat_ttl if timeout is None else max(1, int(timeout))
        safe_key = sanitize_cache_key(key)
        now = self._time()
        with self._local_repeat_guard:
            expired = [
                stored_key
                for stored_key, (expires_at, _value) in self._local_repeat_entries.items()
                if expires_at <= now
            ]
            for stored_key in expired:
                self._local_repeat_entries.pop(stored_key, None)
            self._local_repeat_entries[safe_key] = (now + ttl, value)
            self._local_repeat_entries.move_to_end(safe_key)
            while len(self._local_repeat_entries) > self.local_repeat_max_entries:
                self._local_repeat_entries.popitem(last=False)

    def _prune_negative_entries(self, now):
        """Remove expired local misses while the negative-cache lock is held."""
        expired_keys = [
            key
            for key, expires_at in self._negative_entries.items()
            if expires_at <= now
        ]
        for key in expired_keys:
            self._negative_entries.pop(key, None)

    def get(self, key):
        """Retrieve data from the cache by key."""
        self._ensure_backend_available()
        try:
            cached_data = self.redis_client.get(key)
        except RedisError as exc:
            self._mark_backend_unavailable()
            raise CacheBackendUnavailable("Redis cache read failed") from exc

        self._mark_backend_available()
        if not cached_data:
            return None
        try:
            value = deserialize_cache_entry(cached_data)
            if isinstance(value, dict) and "response_data" in value:
                return Response(
                    response=value["response_data"],
                    status=value["status"],
                    headers=value["headers"],
                )
            return value
        except Exception:
            # Optionally, log the error for debugging
            # print(f"Cache get error: {e}")
            return None

    def set(self, key, value, timeout=120):
        """Set data in the cache with a checksum for integrity."""
        try:
            self._ensure_backend_available()
        except CacheBackendUnavailable:
            return

        try:
            if isinstance(value, Response):
                # Streaming responses should not be cached; forcing them through
                # get_data would buffer the entire payload and defeat streaming.
                if getattr(value, "is_streamed", False):
                    return
                # Persist only essential headers to reduce cache footprint
                content_type = value.headers.get("Content-Type")
                minimal_headers = {"Content-Type": content_type} if content_type else {}
                value = {
                    "response_data": value.get_data(as_text=True),
                    "status": value.status_code,
                    "headers": minimal_headers,
                }
            key = sanitize_cache_key(key)
            serialized_payload = serialize_cache_entry(value)
            self.redis_client.setex(
                key,
                apply_ttl_jitter(timeout, key=key),
                serialized_payload,
            )
        except RedisError as exc:
            self._mark_backend_unavailable()
            logger.warning("Redis cache write failed: %s", exc)
        except Exception:
            logger.exception("Cache value serialization failed")

    def delete(self, key):
        """Delete data from the cache by key."""
        self._ensure_backend_available()
        try:
            self.redis_client.delete(key)
        except RedisError as exc:
            self._mark_backend_unavailable()
            raise CacheBackendUnavailable("Redis cache delete failed") from exc
        self._mark_backend_available()

# Initialize a global cache manager
cache_manager = CacheManager(redis_client)

def kev_cache(
    timeout=120,
    key_prefix="cache_",
    query_string=False,
    canonical_args=None,
    include_path=True,
    cache_if=None,
    uncached_rate_limit=None,
    miss_rate_limit=None,
    rate_limit_bucket=None,
    rate_limit_window=RATE_LIMIT_WINDOW_SECONDS,
    negative_timeout=NEGATIVE_CACHE_TIMEOUT,
):
    """Cache Flask responses using route-aware, optionally canonical query keys.

    ``query_string`` may be ``True`` to preserve the raw query string or a
    callable that returns validated canonical query items. A canonicalizer may
    raise ``ValueError`` to reject a request with a fixed client-safe message
    before cache or origin access.

    ``canonical_args`` performs the same validation and normalization for path
    arguments. ``include_path=False`` lets public aliases share one logical
    cache entry. ``cache_if`` receives the canonical query items and can bypass
    caching for valid high-cardinality requests. Uncached variants and cache
    misses can use separate shared Redis admission budgets so multiple workers
    cannot collectively overwhelm MongoDB.
    """
    def decorator(func):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            # Skip self (args[0]) if this is a method
            method_args = args[1:] if args and hasattr(args[0], '__class__') else args

            if callable(canonical_args):
                try:
                    method_args = canonical_args(*args, **kwargs)
                    cache_kwargs = {}
                except ValueError:
                    return make_response(
                        {"message": "Invalid path parameters"},
                        400,
                    )
            else:
                cache_kwargs = kwargs

            prefix_value = key_prefix
            if callable(prefix_value):
                prefix_value = prefix_value(*args, **kwargs)

            path = (
                request.path
                if include_path and has_request_context()
                else None
            )
            query_items = None
            if has_request_context() and callable(query_string):
                try:
                    query_items = query_string()
                except ValueError:
                    return make_response(
                        {"message": "Invalid query parameters"},
                        400,
                    )
            elif query_string and has_request_context():
                query_items = list(request.args.lists())

            cache_context = {
                "method_args": method_args,
                "kwargs": cache_kwargs,
                "query_items": query_items,
                "path": path,
            }
            cache_key = build_cache_key(
                prefix_value,
                f"{func.__module__}.{func.__qualname__}",
                cache_context,
            )

            admission_bucket = rate_limit_bucket or (
                f"{func.__module__}_{func.__qualname__}"
            )

            # Uncached variants still share one zero-wait fill slot per exact
            # query and one cross-worker budget for the broader route family.
            if callable(cache_if) and not cache_if(query_items):
                local_hit = cache_manager.get_local_repeat(cache_key)
                if local_hit is not None:
                    return local_hit
                try:
                    with cache_manager.singleflight(
                        f"uncached_{cache_key}",
                        wait_seconds=0,
                    ) as acquired:
                        if not acquired:
                            return make_response(
                                {"error": "Origin temporarily busy"},
                                503,
                            )
                        local_hit = cache_manager.get_local_repeat(cache_key)
                        if local_hit is not None:
                            return local_hit
                        try:
                            cache_manager.enforce_rate_limit(
                                admission_bucket,
                                uncached_rate_limit,
                                rate_limit_window,
                            )
                        except OriginRateLimitExceeded:
                            return _rate_limit_response(rate_limit_window)
                        except CacheBackendUnavailable:
                            return make_response(
                                {"error": "Cache temporarily unavailable"},
                                503,
                            )
                        try:
                            result = func(*args, **kwargs)
                        except PyMongoError:
                            return make_response(
                                {"error": "Backend temporarily unavailable"},
                                503,
                            )
                        cache_manager.remember_local_repeat(cache_key, result)
                        return result
                except CacheBackendUnavailable:
                    return make_response(
                        {"error": "Cache temporarily unavailable"},
                        503,
                    )

            # Debug: print cache key
            # print(f"[kev_cache] Cache key: {cache_key}")

            try:
                cached_data = cache_manager.get(cache_key)
            except CacheBackendUnavailable:
                # Redis pressure must not become an unbounded MongoDB fallback.
                return make_response(
                    {"error": "Cache temporarily unavailable"},
                    503,
                )
            if cached_data is not None:
                # print(f"[kev_cache] Cache hit for key: {cache_key}")
                return cached_data

            try:
                with cache_manager.singleflight(cache_key) as acquired:
                    if not acquired:
                        return make_response(
                            {"error": "Origin temporarily busy"},
                            503,
                        )

                    # A concurrent leader may have filled the key while this
                    # request waited, so recheck before calling the origin.
                    try:
                        cached_data = cache_manager.get(cache_key)
                    except CacheBackendUnavailable:
                        return make_response(
                            {"error": "Cache temporarily unavailable"},
                            503,
                        )
                    if cached_data is not None:
                        return cached_data

                    try:
                        cache_manager.enforce_rate_limit(
                            admission_bucket,
                            miss_rate_limit,
                            rate_limit_window,
                        )
                    except OriginRateLimitExceeded:
                        return _rate_limit_response(rate_limit_window)
                    except CacheBackendUnavailable:
                        return make_response(
                            {"error": "Cache temporarily unavailable"},
                            503,
                        )

                    try:
                        result = func(*args, **kwargs)
                    except PyMongoError:
                        return make_response(
                            {"error": "Backend temporarily unavailable"},
                            503,
                        )
                    # Normalize every Flask-supported return form before serialization
                    # so cache hits preserve status, body, and essential headers.
                    response = make_response(result)
                    # Server errors are transient and must not outlive recovery.
                    # 4xx uses the same TTL as 2xx so status cannot be inferred
                    # from cache lifetime.
                    if response.status_code < 500:
                        cache_manager.set(cache_key, response, timeout=timeout)
                    return result
            except CacheBackendUnavailable:
                return make_response(
                    {"error": "Cache temporarily unavailable"},
                    503,
                )
        return wrapper
    return decorator


def _rate_limit_response(window_seconds):
    """Return a retryable response without exposing admission internals."""
    response = make_response({"error": "Origin rate limit exceeded"}, 429)
    response.headers["Retry-After"] = str(max(1, int(window_seconds)))
    return response
