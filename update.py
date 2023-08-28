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
        # Check if the cveID already exists in the database
        # if it does, skip. If it does not exist, insert the vulnerability and print the newly inserted vulnerability
        if collection.find_one({"cveID": vulnerability["cveID"]}):
            #print(f"{vulnerability['cveID']} already exists in database. Skipping.")
            continue
        else:
            collection.insert_one(vulnerability)
            print(f"Inserted vulnerability {vulnerability['cveID']} into the database.")
    client.close()

if __name__ == "__main__":
    # Fetch data from the URL
    data = get_data_from_url(DATA_URL)
    if data:
        # Insert or update data in MongoDB
        insert_data_to_mongodb(data)
