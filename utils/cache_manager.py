import functools
import hashlib
from flask import Response
from utils.cache_config import redis_client
import re

# Regular expression for safe cache keys
SAFE_KEY_RE = re.compile(r"^[\w\-:]+$")

def sanitize_cache_key(key):
    """Ensure cache keys are safe and valid."""
    if not SAFE_KEY_RE.match(key):
        raise ValueError(f"Unsafe cache key: {key}")
    return key

import orjson
from bson import ObjectId
from datetime import datetime

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

class CacheManager:
    def __init__(self, redis_client):
        self.redis_client = redis_client

    def get(self, key):
        """Retrieve data from the cache by key."""
        cached_data = self.redis_client.get(key)
        if not cached_data:
            return None
        try:
            # orjson.loads expects bytes
            cached_data = orjson.loads(cached_data)
            value = cached_data.get("value")
            stored_checksum = cached_data.get("checksum")
            generated_checksum = generate_checksum(value)
            if generated_checksum != stored_checksum:
                raise ValueError("Cache integrity check failed.")
            if isinstance(value, dict) and "response_data" in value:
                return Response(
                    response=value["response_data"],
                    status=value["status"],
                    headers=value["headers"],
                )
            return value
        except Exception as e:
            # Optionally, log the error for debugging
            # print(f"Cache get error: {e}")
            return None

    def set(self, key, value, timeout=120):
        """Set data in the cache with a checksum for integrity."""
        try:
            if isinstance(value, Response):
                value = {
                    "response_data": value.get_data(as_text=True),
                    "status": value.status_code,
                    "headers": dict(value.headers),
                }
            checksum = generate_checksum(value)
            key = sanitize_cache_key(key)
            cache_payload = {"value": value, "checksum": checksum}
            safe_payload = make_orjson_safe(cache_payload)
            serialized_payload = orjson.dumps(safe_payload, option=orjson.OPT_SORT_KEYS)
            self.redis_client.setex(key, timeout, serialized_payload)
        except Exception as e:
            # Optionally, log the error for debugging
            # print(f"Cache set error: {e}")
            pass

    def delete(self, key):
        """Delete data from the cache by key."""
        self.redis_client.delete(key)

# Initialize a global cache manager
cache_manager = CacheManager(redis_client)

def kev_cache(timeout=120, key_prefix="cache_", query_string=False):
    def decorator(func):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            import orjson
            # Skip self (args[0]) if this is a method
            method_args = args[1:] if args and hasattr(args[0], '__class__') else args

            key_parts = [key_prefix, func.__name__]
            if method_args:
                args_hash = hashlib.sha256(
                    orjson.dumps(make_orjson_safe(method_args), option=orjson.OPT_SORT_KEYS)
                ).hexdigest()
                key_parts.append(f"args_{args_hash}")

            if kwargs:
                kwargs_hash = hashlib.sha256(
                    orjson.dumps(make_orjson_safe(dict(sorted(kwargs.items()))), option=orjson.OPT_SORT_KEYS)
                ).hexdigest()
                key_parts.append(f"kwargs_{kwargs_hash}")

            cache_key = "_".join(key_parts)

            if query_string:
                from flask import request
                query_params = str(sorted(request.args.items()))
                query_hash = hashlib.sha256(query_params.encode('utf-8')).hexdigest()
                cache_key += f"_query_{query_hash}"

            # Sanitize the generated cache key
            cache_key = sanitize_cache_key(cache_key)

            # Debug: print cache key
            # print(f"[kev_cache] Cache key: {cache_key}")

            cached_data = cache_manager.get(cache_key)
            if cached_data:
                # print(f"[kev_cache] Cache hit for key: {cache_key}")
                return cached_data

            # print(f"[kev_cache] Cache miss for key: {cache_key}")
            result = func(*args, **kwargs)
            cache_manager.set(cache_key, result, timeout=timeout)
            return result
        return wrapper
    return decorator