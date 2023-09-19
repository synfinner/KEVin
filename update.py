#!/usr/bin/env python3

import json
import requests
from pymongo import MongoClient

# load env using python-dotenv
from dotenv import load_dotenv
load_dotenv()
import os

# MongoDB configuration
MONGO_URI = os.getenv("MONGODB_URI_PROD")
DB_NAME = "kev"
COLLECTION_NAME = "vulns"

client = MongoClient(MONGO_URI)
db = client[DB_NAME]
collection = db[COLLECTION_NAME]

# URL for the JSON data
DATA_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

def stream_data_from_url(url):
    response = requests.get(url, stream=True)
    if response.status_code == 200:
        data = response.json()  # Parse the entire JSON response
        if "vulnerabilities" in data:
            for vulnerability in data["vulnerabilities"]:
                yield vulnerability
    else:
        print("Failed to fetch data from URL.")
        yield None  # Yield None to handle the error case

def insert_data_to_mongodb(data):
    for vulnerability in data:
        if not collection.find_one({"cveID": vulnerability["cveID"]}):
            collection.insert_one(vulnerability)
            print(f"Inserted vulnerability {vulnerability['cveID']} into the database.")

if __name__ == "__main__":
    # Stream and insert data
    data_stream = stream_data_from_url(DATA_URL)
    insert_data_to_mongodb(data_stream)

client.close()