#!/usr/bin/env python3

import re
from urllib.parse import unquote
from flask import Flask, jsonify, request
from flask_restful import Api, Resource, reqparse
from pymongo import MongoClient
from datetime import datetime, timedelta
from flask_caching import Cache
from schema.serializers import serialize_vulnerability, serialize_all_vulnerability, nvd_seralizer

# load env using python-dotenv
from dotenv import load_dotenv
load_dotenv()
import os

app = Flask(__name__)
# Configure cache
cache = Cache(app, config={'CACHE_TYPE': 'simple', 'CACHE_DEFAULT_TIMEOUT': 300})  # 300 seconds = 5 minutes
api = Api(app)

# MongoDB configuration
MONGO_URI = os.getenv("MONGO_URI_DEV")
DB_NAME = "kev"
COLLECTION_NAME = "vulns"

# Connect to MongoDB
client = MongoClient(MONGO_URI)
db = client[DB_NAME]
collection = db[COLLECTION_NAME]

# Define a new mongodb db and collection for all vuln data
ALL_VULNS_DB_NAME = "cveland"
ALL_VULNS_COLLECTION_NAME = "cves"
all_vulns_db = client[ALL_VULNS_DB_NAME]
all_vulns_collection = all_vulns_db[ALL_VULNS_COLLECTION_NAME]

#Function for sanitizing input
def sanitize_query(query):
    # URL decode the query
    query = unquote(query)
    # Allow alphanumeric characters, spaces, and common punctuation
    query = re.sub(r"[^a-zA-Z0-9\s-]", "", query)
    # Remove extra whitespace from query
    query = re.sub(r"\s+", " ", query)
    return query

# Resource for fectching mitre and nvd data from the cveland via CVE-ID, which is the _id field in the cveland collection
class cveLandResource(Resource):
    @cache.cached()
    def get(self, cve_id):
        # Sanitize the input CVE ID
        sanitized_cve_id = sanitize_query(cve_id)
        vulnerability = all_vulns_collection.find_one({"_id": sanitized_cve_id})
        if vulnerability:
            return serialize_all_vulnerability(vulnerability)
        else:
            return {"message": "Vulnerability not found"}, 404

# Resource for NVD data from the cveland via CVE-ID, which is the _id field in the cveland collection
class cveNVDResource(Resource):
    @cache.cached()
    def get(self, cve_id):
        # Sanitize the input CVE ID
        sanitized_cve_id = sanitize_query(cve_id)
        vulnerability = all_vulns_collection.find_one({"_id": sanitized_cve_id})
        if vulnerability:
            return nvd_seralizer(vulnerability)
        else:
            return {"message": "Vulnerability not found"}, 404

# Resource for fetching a specific vulnerability by CVE ID
class VulnerabilityResource(Resource):
    @cache.cached()
    def get(self, cve_id):
        # Sanitize the input CVE ID
        sanitized_cve_id = sanitize_query(cve_id)
        
        vulnerability = collection.find_one({"cveID": sanitized_cve_id})
        if vulnerability:
            return serialize_vulnerability(vulnerability)
        else:
            return {"message": "Vulnerability not found"}, 404

# Resource for fetching all vulnerabilities
class AllVulnerabilitiesResource(Resource):
    def get(self):
        search_query = request.args.get("search", '')
        # Sanitize the search query
        clean_query = sanitize_query(search_query)
        # Check if the data is already cached
        cached_data = cache.get(clean_query)
        if cached_data is not None:
            vulnerabilities = cached_data
        else:
            if clean_query:
                # Search for vulnerabilities that match the query
                cursor = collection.find({"$text": {"$search": clean_query}})
            else:
                # No query provided, return all data
                cursor = collection.find()
            # Convert the cursor data to a list
            vulnerabilities = [serialize_vulnerability(v) for v in cursor]
            # Cache the data
            cache.set(clean_query, vulnerabilities)
        return vulnerabilities

# Resource for fetching new vulnerabilities added in the last X days
class NewVulnerabilitiesResource(Resource):
    @cache.cached()
    def get(self, days):
        # Sanitize the input days value
        sanitized_days = sanitize_query(str(days))
        # Validate the sanitized days value
        try:
            sanitized_days = int(sanitized_days)
            if sanitized_days < 0:
                raise ValueError
        except ValueError:
            return {"message": "Invalid value for days"}, 400
        
        # Calculate the cutoff date for new vulnerabilities
        cutoff_date = datetime.utcnow() - timedelta(days=sanitized_days)
        all_vulnerabilities = collection.find()

        new_vulnerabilities = []
        for vulnerability in all_vulnerabilities:
            date_added_str = vulnerability.get("dateAdded")
            try:
                date_added = datetime.strptime(date_added_str, "%Y-%m-%d")
                if date_added >= cutoff_date:
                    new_vulnerabilities.append(serialize_vulnerability(vulnerability))
            except ValueError:
                pass  # Ignore invalid date formats

        return new_vulnerabilities

    

# Define error handler for 500s
@app.errorhandler(500)
def internal_server_error(e):
    return jsonify({"error": "Internal server error! Synfinner probably broke something."}), 500

# Define error handler for 404s
@app.errorhandler(404)
def not_found(e):
    return jsonify({"error": "You found nothing! Congratulations!"}), 404

# Define resource routes
api.add_resource(VulnerabilityResource, "/kev/<string:cve_id>", strict_slashes=False)
api.add_resource(AllVulnerabilitiesResource, "/kev", strict_slashes=False) 
api.add_resource(NewVulnerabilitiesResource, "/kev/new/<int:days>")
api.add_resource(cveLandResource, "/vuln/<string:cve_id>", strict_slashes=False)
api.add_resource(cveNVDResource, "/vuln/<string:cve_id>/nvd", strict_slashes=False)

if __name__ == "__main__":
    app.run(debug=False)
