import json
import functools
import hashlib
from bson import ObjectId
from flask import Response
from utils.cache_config import redis_client
from utils.jencoder import jencoder  # Import your custom encoder
import re

# Regular expression for safe cache keys
SAFE_KEY_RE = re.compile(r"^[\w\-:]+$")

def sanitize_cache_key(key):
    """Ensure cache keys are safe and valid."""
    if not SAFE_KEY_RE.match(key):
        raise ValueError(f"Unsafe cache key: {key}")
    return key

def generate_checksum(data):
    """
    Generate a checksum for the given data.
    Use consistent serialization with jencoder to avoid checksum mismatches.
    Ensure strings are encoded as bytes before hashing.
    """
    if isinstance(data, (dict, list)):
        serialized = json.dumps(data, sort_keys=True, cls=jencoder)  # Serialize with jencoder
        data_bytes = serialized.encode("utf-8")  # Convert serialized string to bytes
    elif isinstance(data, str):
        data_bytes = data.encode("utf-8")  # Convert string to bytes
    else:
        serialized = json.dumps(data, cls=jencoder)  # Serialize other types
        data_bytes = serialized.encode("utf-8")  # Convert serialized string to bytes
    
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
            cached_data = json.loads(cached_data)  # Deserialize cached data
            value = cached_data.get("value")
            stored_checksum = cached_data.get("checksum")

            # Generate checksum for validation
            generated_checksum = generate_checksum(value)

            # Debugging: Print both checksums
            #print(f"Stored checksum: {stored_checksum}")
            #print(f"Generated checksum: {generated_checksum}")

            if generated_checksum != stored_checksum:
                raise ValueError("Cache integrity check failed.")

            # Reconstruct Flask.Response if applicable
            if isinstance(value, dict) and "response_data" in value:
                return Response(
                    response=value["response_data"],
                    status=value["status"],
                    headers=value["headers"],
                )
            return value
        except:
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

            # Serialize value and generate checksum
            serialized_value = json.dumps(value, cls=jencoder)  # Serialize with jencoder
            checksum = generate_checksum(value)  # Generate checksum using the same serialized value
            key = sanitize_cache_key(key)

            # Debugging: Print checksum and serialized value
            #print(f"Generated checksum during set: {checksum}")
            #print(f"Serialized value during set: {serialized_value}")

            # Store value and checksum together
            self.redis_client.setex(
                key, timeout, json.dumps({"value": value, "checksum": checksum}, cls=jencoder)
            )
        except:
            # continue without caching if an error occurs
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
            cache_key = f"{key_prefix}{func.__name__}_"
            cache_key += "_".join([str(arg) for arg in args]) + "_"
            cache_key += "_".join([f"{k}_{v}" for k, v in kwargs.items()])

            if query_string:
                from flask import request
                query_params = str(sorted(request.args.items()))
                cache_key += f"_query_{hash(query_params)}"

            # Sanitize the generated cache key
            cache_key = sanitize_cache_key(cache_key)

            cached_data = cache_manager.get(cache_key)
            if cached_data:
                return cached_data

            result = func(*args, **kwargs)
            cache_manager.set(cache_key, result, timeout=timeout)
            return result

        return wrapper
    return decorator