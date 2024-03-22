# Import the Cache class from the flask_caching module
from flask_caching import Cache
# Import the cache_config dictionary from the utils.cache_config module
from utils.cache_config import cache_config

# Create a new Cache object
cache = Cache()

# Define a function to initialize the cache with an app and the cache_config
def init_cache(app):
    """
    Initializes the cache with the given Flask app and cache configuration.

    Parameters:
    app (Flask): The Flask app with which to initialize the cache.

    """
    # Call the init_app method on the cache object, passing in the app and the cache_config
    cache.init_app(app, config=cache_config)