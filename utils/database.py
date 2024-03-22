# Import the MongoClient class from the pymongo module
from pymongo import MongoClient
# Import the os module to interact with the operating system
import os

# Import the load_dotenv function from the python-dotenv module
from dotenv import load_dotenv
# Call the load_dotenv function to load environment variables from a .env file
load_dotenv()

# Get the value of the MONGODB_URI_PROD environment variable
MONGO_URI = os.getenv("MONGODB_URI_PROD")
# Create a new MongoClient object with the MongoDB URI, a maximum pool size of 50, and a minimum pool size of 10
client = MongoClient(MONGO_URI, maxPoolSize=50, minPoolSize=10)

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