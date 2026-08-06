"""Redis cache helpers for KEVin API responses."""

import functools
import hashlib
import hmac
import logging
import os
import threading
import time
from contextlib import contextmanager
from flask import Response, has_request_context, make_response, request
from gevent.lock import Semaphore
from pymongo.errors import PyMongoError
from redis.exceptions import RedisError
from utils.cache_config import redis_client
import re
import orjson
from bson import ObjectId
from datetime import datetime


# Regular expression for safe cache keys
SAFE_KEY_RE = re.compile(r"^[\w\-:]+$")
CACHE_ENVELOPE_PREFIX = b"kevin-cache-v2:"
logger = logging.getLogger(__name__)


class CacheBackendUnavailable(RuntimeError):
    """Signal that Redis is unavailable and origin load must be shed."""


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
    if generate_checksum(value) != stored_checksum:
        raise ValueError("Cache integrity check failed.")
    return value


class CacheManager:
    def __init__(
        self,
        redis_connection,
        circuit_breaker_seconds=None,
        singleflight_wait_seconds=None,
        time_func=None,
    ):
        """Initialize Redis access with a short per-worker failure circuit."""
        self.redis_client = redis_connection
        self.circuit_breaker_seconds = (
            float(os.getenv("CACHE_CIRCUIT_BREAKER_SECONDS", "1"))
            if circuit_breaker_seconds is None
            else max(0.0, float(circuit_breaker_seconds))
        )
        self.singleflight_wait_seconds = (
            float(os.getenv("CACHE_SINGLEFLIGHT_WAIT_SECONDS", "0.25"))
            if singleflight_wait_seconds is None
            else max(0.0, float(singleflight_wait_seconds))
        )
        self._time = time.monotonic if time_func is None else time_func
        self._unavailable_until = 0.0
        self._singleflight_entries = {}
        self._singleflight_guard = threading.Lock()

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

    @contextmanager
    def singleflight(self, key):
        """Yield whether this request acquired the bounded fill slot for key."""
        with self._singleflight_guard:
            entry = self._singleflight_entries.get(key)
            if entry is None:
                entry = _SingleflightEntry()
                self._singleflight_entries[key] = entry
            entry.users += 1

        acquired = entry.lock.acquire(timeout=self.singleflight_wait_seconds)
        try:
            yield acquired
        finally:
            if acquired:
                entry.lock.release()
            with self._singleflight_guard:
                entry.users -= 1
                if entry.users == 0:
                    self._singleflight_entries.pop(key, None)

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
            self.redis_client.setex(key, timeout, serialized_payload)
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

def kev_cache(timeout=120, key_prefix="cache_", query_string=False):
    """Cache Flask responses using route-aware, optionally canonical query keys.

    ``query_string`` may be ``True`` to preserve the raw query string or a
    callable that returns validated canonical query items. A canonicalizer may
    raise ``ValueError`` to reject a request with a fixed client-safe message
    before cache or origin access.
    """
    def decorator(func):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            # Skip self (args[0]) if this is a method
            method_args = args[1:] if args and hasattr(args[0], '__class__') else args

            prefix_value = key_prefix
            if callable(prefix_value):
                prefix_value = prefix_value(*args, **kwargs)

            path = request.path if has_request_context() else None
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
                "kwargs": kwargs,
                "query_items": query_items,
                "path": path,
            }
            cache_key = build_cache_key(
                prefix_value,
                f"{func.__module__}.{func.__qualname__}",
                cache_context,
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
                if response.status_code < 500:
                    cache_manager.set(cache_key, response, timeout=timeout)
                return result
        return wrapper
    return decorator
