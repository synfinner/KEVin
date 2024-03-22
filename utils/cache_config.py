# Import the os module to interact with the operating system
import os

# Import the load_dotenv function from the python-dotenv module
from dotenv import load_dotenv
# Call the load_dotenv function to load environment variables from a .env file
load_dotenv()

# Get the value of the REDIS_IP environment variable
REDIS_IP = os.getenv("REDIS_IP")

# Define a dictionary to hold the configuration for the cache
cache_config = {
    # Specify the type of cache to use (Redis in this case)
    'CACHE_TYPE': 'flask_caching.backends.RedisCache',
    # Specify the default timeout for the cache (in seconds)
    'CACHE_DEFAULT_TIMEOUT': 600,
    # Specify the host for the Redis server
    'CACHE_REDIS_HOST': REDIS_IP,
    # Specify the port for the Redis server
    'CACHE_REDIS_PORT': '6379',
    # Specify a prefix for all keys stored in the cache
    'CACHE_KEY_PREFIX': 'kev_'
}