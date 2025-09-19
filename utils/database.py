# Import the MongoClient class from the pymongo module
from pymongo import MongoClient, errors, ASCENDING
# Import the os module to interact with the operating system
import os
import time  # Import time for sleep functionality
import threading  # Import threading to run the connection check in a separate thread

# Import the load_dotenv function from the python-dotenv module
from dotenv import load_dotenv
# Call the load_dotenv function to load environment variables from a .env file
load_dotenv()

# Import the Queue class from the queue module
from queue import Queue

# Create a queue for logging messages
log_queue = Queue()

def log_output():
    while True:
        message = log_queue.get()
        if message is None:  # Exit condition
            break
        print(message, flush=True)  # Print the message

# Start a logging thread
logging_thread = threading.Thread(target=log_output, daemon=True)
logging_thread.start()

def create_client(uri):
    # Create a new MongoClient object with snappy compression and bounded timeouts
    max_pool = int(os.getenv("MONGO_MAX_POOL_SIZE", 20))
    min_pool = int(os.getenv("MONGO_MIN_POOL_SIZE", 0))
    connect_timeout = int(os.getenv("MONGO_CONNECT_TIMEOUT_MS", 3000))
    socket_timeout = int(os.getenv("MONGO_SOCKET_TIMEOUT_MS", 10000))
    return MongoClient(
        uri,
        maxPoolSize=max_pool,
        minPoolSize=min_pool,
        compressors='snappy',
        serverSelectionTimeoutMS=3000,
        connectTimeoutMS=connect_timeout,
        socketTimeoutMS=socket_timeout,
    )

def ensure_connection(client, uri, max_retries=3):
    for attempt in range(max_retries):
        if check_connection(client):
            # No direct manipulation of the internal queue; rely on consumer thread
            return client
        log_queue.put(f"Connection check failed, attempt {attempt + 1}...")  # Log retry attempt
        time.sleep(5)  # Wait before retrying
    raise Exception("Could not connect to MongoDB after multiple attempts.")

def check_connection(client):
    try:
        # Attempt to get server information to check connection
        client.admin.command('ping')
        return True
    except (errors.ConnectionFailure, errors.ServerSelectionTimeoutError):
        print("Connection check failed.")  # Log the connection failure
        return False

# Get the value of the MONGODB_URI_PROD environment variable
MONGO_URI = os.getenv("MONGODB_URI_PROD")
# Create a new MongoClient object
client = create_client(MONGO_URI)
# Ensure connection with retries
client = ensure_connection(client, MONGO_URI)

# Define the name of the database and the collection
DB_NAME = "kev"
COLLECTION_NAME = "vulns"
# Get the database and the collection from the client
db = client[DB_NAME]
collection = db[COLLECTION_NAME]

# Required indexes to support API sort allowlists without forcing
# collection scans. Keep aligned with ALLOWED_KEV_SORT_FIELDS.
REQUIRED_KEV_INDEXES = [
    ("dateAdded", ASCENDING, "idx_dateAdded"),
    ("dueDate", ASCENDING, "idx_dueDate"),
    ("cveID", ASCENDING, "idx_cveID"),
]


def ensure_collection_indexes(coll, index_specs):
    """Create missing indexes for the given collection and return the final list."""
    try:
        existing_indexes = list(coll.list_indexes())
    except errors.PyMongoError:
        # Avoid crashing application startup if we cannot enumerate indexes.
        return []

    existing_names = {index["name"] for index in existing_indexes}

    for field, direction, name in index_specs:
        if name not in existing_names:
            try:
                coll.create_index([(field, direction)], name=name, background=True)
            except errors.PyMongoError:
                # Best effort – if creation fails we simply continue.
                continue

    # Re-fetch to return an up-to-date snapshot resembling getIndexes().
    try:
        return list(coll.list_indexes())
    except errors.PyMongoError:
        return existing_indexes


KEV_INDEXES_ON_STARTUP = ensure_collection_indexes(collection, REQUIRED_KEV_INDEXES)
if KEV_INDEXES_ON_STARTUP:
    try:
        kev_index_names = [index.get("name", "<unnamed>") for index in KEV_INDEXES_ON_STARTUP]
        print(f"KEV collection indexes on startup: {kev_index_names}")
    except Exception:
        print("KEV collection indexes on startup: <error printing names>")
else:
    print("KEV collection indexes on startup: unavailable")

# Define the name of the all vulnerabilities database and the all vulnerabilities collection
ALL_VULNS_DB_NAME = "cveland"
ALL_VULNS_COLLECTION_NAME = "cves"
# Get the all vulnerabilities database and the all vulnerabilities collection from the client
all_vulns_db = client[ALL_VULNS_DB_NAME]
all_vulns_collection = all_vulns_db[ALL_VULNS_COLLECTION_NAME]

import threading

stop_event = threading.Event()

def monitor_connection(client, uri, stop_event):
    while not stop_event.is_set():
        print("Checking MongoDB connection...")  # Log the connection check
        client = ensure_connection(client, uri)
        stop_event.wait(10)  # Check every 10 seconds or until stopped

# Start the connection monitoring in a separate thread
connection_thread = threading.Thread(target=monitor_connection, args=(client, MONGO_URI, stop_event), daemon=True)
connection_thread.start()

# Ensure to stop the logging thread and monitoring thread when done
log_queue.put(None)  # Signal the logging thread to exit
stop_event.set()  # Signal the monitoring thread to exit
