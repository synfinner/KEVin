import os
from redis import ConnectionPool
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# Define constants for configuration parameters
REDIS_IP = os.getenv("REDIS_IP")
REDIS_PORT = 6379
CACHE_DEFAULT_TIMEOUT = 600
CACHE_KEY_PREFIX = "kev_"
MAX_CONNECTIONS = 20
TIMEOUT = 5

def setup_cache_config(redis_ip):
    # Create a connection pool for Redis
    pool = ConnectionPool(host=redis_ip, port=REDIS_PORT, max_connections=MAX_CONNECTIONS, timeout=TIMEOUT)

    # Define the cache configuration
    cache_config = {
        'CACHE_TYPE': 'flask_caching.backends.RedisCache',
        'CACHE_DEFAULT_TIMEOUT': CACHE_DEFAULT_TIMEOUT,
        'CACHE_REDIS_HOST': redis_ip,
        'CACHE_REDIS_PORT': REDIS_PORT,
        'CACHE_KEY_PREFIX': CACHE_KEY_PREFIX,
        'CACHE_REDIS_CONNECTION_POOL': pool
    }

    return cache_config

# Set up cache configuration
cache_config = setup_cache_config(REDIS_IP)
