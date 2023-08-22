#!/usr/bin/env python3

import json
import requests
from pymongo import MongoClient

# MongoDB configuration
MONGO_URI = "mongodb://localhost:27017/"
DB_NAME = "kev"
COLLECTION_NAME = "vulns"

# URL for the JSON data
DATA_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

def get_data_from_url(url):
    response = requests.get(url)
    if response.status_code == 200:
        return response.json()
    else:
        print("Failed to fetch data from URL.")
        return None

def insert_data_to_mongodb(data):
    client = MongoClient(MONGO_URI)
    db = client[DB_NAME]
    collection = db[COLLECTION_NAME]

    # Insert or update each vulnerability in the data
    for vulnerability in data["vulnerabilities"]:
        query = {"cveID": vulnerability["cveID"]}
        collection.update_one(query, {"$set": vulnerability}, upsert=True)
    
    client.close()

if __name__ == "__main__":
    # Fetch data from the URL
    data = get_data_from_url(DATA_URL)
    if data:
        # Insert or update data in MongoDB
        insert_data_to_mongodb(data)
