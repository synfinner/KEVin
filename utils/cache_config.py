
import os

# Load env using python-dotenv
from dotenv import load_dotenv
load_dotenv()

REDIS_IP = os.getenv("REDIS_IP")

cache_config = {
    'CACHE_TYPE': 'redis',
    'CACHE_DEFAULT_TIMEOUT': 600,
    'CACHE_REDIS_HOST': REDIS_IP,
    'CACHE_REDIS_PORT': '6379',
    'CACHE_KEY_PREFIX': 'kev_'
}

