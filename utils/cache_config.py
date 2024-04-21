import os
from redis import ConnectionPool
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# Constants for Redis configuration
REDIS_PORT = int(os.getenv("REDIS_PORT", 6379))
CACHE_DEFAULT_TIMEOUT = int(os.getenv("CACHE_DEFAULT_TIMEOUT", 600))
CACHE_KEY_PREFIX = os.getenv("CACHE_KEY_PREFIX", "kev_")
MAX_CONNECTIONS = int(os.getenv("MAX_CONNECTIONS", 20))
TIMEOUT = int(os.getenv("TIMEOUT", 5))

def setup_cache_config(redis_host, redis_port=REDIS_PORT, max_connections=MAX_CONNECTIONS, timeout=TIMEOUT,
                       cache_default_timeout=CACHE_DEFAULT_TIMEOUT, cache_key_prefix=CACHE_KEY_PREFIX):
    """
    Set up cache configuration with a Redis backend.
    Parameters are configurable with sensible defaults.
    """
    if not redis_host:
        raise ValueError("Redis host must be specified")

    # Create a connection pool for Redis
    pool = ConnectionPool(host=redis_host, port=redis_port, max_connections=max_connections, timeout=timeout)

    # Define the cache configuration
    cache_config = {
        'CACHE_TYPE': 'flask_caching.backends.RedisCache',
        'CACHE_DEFAULT_TIMEOUT': cache_default_timeout,
        'CACHE_REDIS_HOST': redis_host,
        'CACHE_REDIS_PORT': redis_port,
        'CACHE_KEY_PREFIX': cache_key_prefix,
        'CACHE_REDIS_CONNECTION_POOL': pool
    }

    return cache_config

# Example usage:
try:
    redis_ip = os.getenv("REDIS_IP")
    if not redis_ip:
        raise EnvironmentError("REDIS_IP environment variable not set")
    cache_config = setup_cache_config(redis_ip)
except Exception as e:
    print(f"Error setting up cache configuration: {e}")
