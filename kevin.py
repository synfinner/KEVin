#!/usr/bin/env python3

import re
from urllib.parse import unquote
from flask import Flask, jsonify, request
from flask_restful import Api, Resource, reqparse
from flask import render_template
from pymongo import MongoClient
from datetime import datetime, timedelta
from flask_caching import Cache
from schema.serializers import serialize_vulnerability, serialize_all_vulnerability, nvd_seralizer, mitre_seralizer

# load env using python-dotenv
from dotenv import load_dotenv
load_dotenv()
import os

app = Flask(__name__)
# Configure cache
cache = Cache(app, config={'CACHE_TYPE': 'simple', 'CACHE_DEFAULT_TIMEOUT': 300})  # 300 seconds = 5 minutes
api = Api(app)

# MongoDB configuration
MONGO_URI = os.getenv("MONGODB_URI_PROD")
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

# Route for the root endpoint ("/")
@app.route("/")
@cache.cached()
def index():
    return render_template("index.html")

# Route for example page ("/example")
@app.route("/examples")
@cache.cached()
def example():
    return render_template("example.html")

@app.route('/get_metrics')
@cache.cached()
def get_metrics():
    kevs_count = collection.count_documents({})
    cves_count = all_vulns_collection.count_documents({})

    metrics = {
        'cves_count': cves_count,
        'kevs_count': kevs_count,
    }

    return jsonify(metrics)

#Function for sanitizing input
def sanitize_query(query):
    # URL decode the query
    query = unquote(query)
    # Allow alphanumeric characters, spaces, and common punctuation
    query = re.sub(r"[^a-zA-Z0-9\s-]", "", query)
    # Remove extra whitespace from query
    query = query.strip()
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
        
# Resource for Mitre data from the cveland via CVE-ID, which is the _id field in the cveland collection
class cveMitreResource(Resource):
    @cache.cached()
    def get(self, cve_id):
        # Sanitize the input CVE ID
        sanitized_cve_id = sanitize_query(cve_id)
        vulnerability = all_vulns_collection.find_one({"_id": sanitized_cve_id})
        if vulnerability:
            return mitre_seralizer(vulnerability)
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
class AllKevVulnerabilitiesResource(Resource):
    def get(self):
        valid_sort_params = {"severity"}  # Add more valid sort parameters if needed
        valid_order_params = {"asc", "desc"}
        
        search_query = request.args.get("search", '')
        sort_param = request.args.get("sort", "severity")
        order_param = request.args.get("order", "asc")
        
        clean_query = sanitize_query(search_query)
        sanitized_sort_param = sanitize_query(sort_param)
        sanitized_order_param = sanitize_query(order_param)
        
        if sanitized_sort_param not in valid_sort_params or sanitized_order_param not in valid_order_params:
            return {"message": "Invalid sorting parameters"}, 400
        
        cached_key = f"{clean_query}_{sanitized_sort_param}_{sanitized_order_param}"
        cached_data = cache.get(cached_key)
        
        if cached_data is not None:
            vulnerabilities = cached_data
        else:
            if clean_query:
                cursor = collection.find({"$text": {"$search": clean_query}})
            else:
                cursor = collection.find()
            
            if sanitized_sort_param == "severity":
                sorted_vulnerabilities = []
                for vulnerability in cursor:
                    nvd_data = vulnerability.get('nvdData', [])
                    if nvd_data and nvd_data[0].get('baseScore') is not None:
                        sorted_vulnerabilities.append(vulnerability)

                sorted_vulnerabilities.sort(key=lambda v: v['nvdData'][0]['baseScore'], reverse=(sanitized_order_param == "desc"))
                vulnerabilities = [serialize_vulnerability(v) for v in sorted_vulnerabilities]
            else:
                vulnerabilities = [serialize_vulnerability(v) for v in cursor]
            
            cache.set(cached_key, vulnerabilities)
        
        return vulnerabilities

# Resource for fetching recent vulnerabilities
class RecentKevVulnerabilitiesResource(Resource):
    @cache.cached(timeout=10)
    def get(self):
        days = request.args.get("days", type=int)
        if days is None or days < 0:
            return {"message": "Invalid value for days"}, 400

        cutoff_date = datetime.utcnow() - timedelta(days=days)
        recent_vulnerabilities = []

        cursor = collection.find()
        for vulnerability in cursor:
            date_added_str = vulnerability.get("dateAdded")
            try:
                date_added = datetime.strptime(date_added_str, "%Y-%m-%d")
                if date_added >= cutoff_date:
                    recent_vulnerabilities.append(
                        serialize_vulnerability(vulnerability)
                    )
            except ValueError as e:
                pass  # Ignore invalid date formats

        return recent_vulnerabilities


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
api.add_resource(AllKevVulnerabilitiesResource, "/kev", strict_slashes=False)
api.add_resource(RecentKevVulnerabilitiesResource, "/kev/recent", strict_slashes=False) 
api.add_resource(cveLandResource, "/vuln/<string:cve_id>", strict_slashes=False)
api.add_resource(cveNVDResource, "/vuln/<string:cve_id>/nvd", strict_slashes=False)
api.add_resource(cveMitreResource, "/vuln/<string:cve_id>/mitre", strict_slashes=False)

if __name__ == "__main__":
    app.run(debug=False)
