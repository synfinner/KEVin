from pymongo import MongoClient
import os

# Load env using python-dotenv
from dotenv import load_dotenv
load_dotenv()

MONGO_URI = os.getenv("MONGODB_URI_PROD")
client = MongoClient(MONGO_URI, maxPoolSize=50, minPoolSize=10)

DB_NAME = "kev"
COLLECTION_NAME = "vulns"
db = client[DB_NAME]
collection = db[COLLECTION_NAME]

ALL_VULNS_DB_NAME = "cveland"
ALL_VULNS_COLLECTION_NAME = "cves"
all_vulns_db = client[ALL_VULNS_DB_NAME]
all_vulns_collection = all_vulns_db[ALL_VULNS_COLLECTION_NAME]
