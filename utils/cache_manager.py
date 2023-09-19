from flask_caching import Cache
from utils.cache_config import cache_config

cache = Cache()

def init_cache(app):
    cache.init_app(app, config=cache_config)
