# Import the MongoClient class from the pymongo module
from pymongo import MongoClient, errors
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
        log_queue.queue.clear()  # Clear the queue after printing

# Start a logging thread
logging_thread = threading.Thread(target=log_output, daemon=True)
logging_thread.start()

def create_client(uri):
    # Create a new MongoClient object with snappy compression
    return MongoClient(uri, maxPoolSize=50, minPoolSize=10, compressors='snappy', serverSelectionTimeoutMS=3000)

def ensure_connection(client, uri, max_retries=3):
    for attempt in range(max_retries):
        if check_connection(client):
            log_queue.queue.clear()  # Clear the queue on successful connection
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
MONGO_URI = os.getenv("MONGODB_URI_DEV")
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