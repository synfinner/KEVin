import os
from redis import StrictRedis, ConnectionPool
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# Constants for Redis configuration
REDIS_PORT = int(os.getenv("REDIS_PORT", 6379))
CACHE_DEFAULT_TIMEOUT = int(os.getenv("CACHE_DEFAULT_TIMEOUT", 600))  # Default cache timeout
CACHE_KEY_PREFIX = os.getenv("CACHE_KEY_PREFIX", "kev_")
MAX_CONNECTIONS = int(os.getenv("MAX_CONNECTIONS", 20))
SOCKET_TIMEOUT = int(os.getenv("SOCKET_TIMEOUT", 10))  # Socket timeout for Redis connections in seconds
SOCKET_CONNECT_TIMEOUT = int(os.getenv("SOCKET_CONNECT_TIMEOUT", 10))  # Timeout for establishing a connection

def setup_cache_config(redis_host):
    """
    Set up cache configuration with a Redis backend.
    Parameters are configurable with sensible defaults.
    """
    if not redis_host:
        raise ValueError("Redis host must be specified")

    # Create a connection pool for Redis with proper timeouts
    pool = ConnectionPool(
        host=redis_host,
        port=REDIS_PORT,
        db=0,  # Default Redis DB
        max_connections=MAX_CONNECTIONS,
        socket_timeout=SOCKET_TIMEOUT,  # Timeout for socket operations
        socket_connect_timeout=SOCKET_CONNECT_TIMEOUT  # Timeout for connection establishment
    )

    # Create a Redis client using the connection pool
    redis_client = StrictRedis(connection_pool=pool)
    
    # Cache configuration details
    cache_config = {
        'CACHE_REDIS_HOST': redis_host,
        'CACHE_REDIS_PORT': REDIS_PORT,
        'CACHE_KEY_PREFIX': CACHE_KEY_PREFIX,
        'CACHE_REDIS_CONNECTION_POOL': pool
    }

    return redis_client, cache_config

# Example usage:
try:
    redis_ip = os.getenv("REDIS_IP")
    if not redis_ip:
        raise EnvironmentError("REDIS_IP environment variable not set")
    redis_client, cache_config = setup_cache_config(redis_ip)
    print("Redis cache configured successfully!")
except Exception as e:
    print(f"Error setting up cache configuration: {e}")