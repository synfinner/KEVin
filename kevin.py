#!/usr/bin/env python3

from flask import Flask, jsonify
from flask_restful import Api, Resource, reqparse
from pymongo import MongoClient
from datetime import datetime, timedelta
from flask_caching import Cache
from schema.serializers import serialize_vulnerability

app = Flask(__name__)
# Configure cache
cache = Cache(app, config={'CACHE_TYPE': 'simple', 'CACHE_DEFAULT_TIMEOUT': 300})  # 300 seconds = 5 minutes
api = Api(app)

# MongoDB configuration
MONGO_URI = "mongodb://localhost:27017/"
DB_NAME = "kev"
COLLECTION_NAME = "vulns"

# Connect to MongoDB
client = MongoClient(MONGO_URI)
db = client[DB_NAME]
collection = db[COLLECTION_NAME]

# Resource for fetching a specific vulnerability by CVE ID
class VulnerabilityResource(Resource):
    @cache.cached()
    def get(self, cve_id):
        vulnerability = collection.find_one({"cveID": cve_id})
        if vulnerability:
            return serialize_vulnerability(vulnerability)
        else:
            return {"message": "Vulnerability not found"}, 404

# Resource for fetching all vulnerabilities
class AllVulnerabilitiesResource(Resource):
    @cache.cached()
    def get(self):
        vulnerabilities = collection.find()
        result = [serialize_vulnerability(v) for v in vulnerabilities]
        return result

# Resource for fetching new vulnerabilities added in the last X days
class NewVulnerabilitiesResource(Resource):
    @cache.cached()
    def get(self, days):
        # Calculate the cutoff date for new vulnerabilities
        cutoff_date = datetime.utcnow() - timedelta(days=days)
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

# Define error handler for 404s
@app.errorhandler(404)
def not_found(e):
    return jsonify({"error": "You found nothing! Congratulations!"}), 404

# Define resource routes
api.add_resource(VulnerabilityResource, "/kev/<string:cve_id>")
api.add_resource(AllVulnerabilitiesResource, "/kev") 
api.add_resource(NewVulnerabilitiesResource, "/kev/new/<int:days>")

if __name__ == "__main__":
    app.run(debug=False)
