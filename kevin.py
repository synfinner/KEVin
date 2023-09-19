#!/usr/bin/env python3

import re
import math
from urllib.parse import unquote
from flask import Flask, jsonify, request
from flask_restful import Api, Resource, reqparse
from flask import render_template
from flask_compress import Compress
from pymongo import MongoClient
from pymongo import DESCENDING,ASCENDING
from datetime import datetime, timedelta
from flask_caching import Cache
from schema.serializers import serialize_vulnerability, serialize_all_vulnerability, nvd_seralizer, mitre_seralizer
from modules.reportgen import report_gen

# load env using python-dotenv
from dotenv import load_dotenv
load_dotenv()
import os

app = Flask(__name__)
# Configure cache
#cache = Cache(app, config={'CACHE_TYPE': 'simple', 'CACHE_DEFAULT_TIMEOUT': 300})  # 300 seconds = 5 minutes
REDIS_IP = os.getenv("REDIS_IP")
cache_config = {
    'CACHE_TYPE': 'redis',
    'CACHE_DEFAULT_TIMEOUT': 600,  # 300 seconds = 5 minutes
    'CACHE_REDIS_HOST': REDIS_IP,
    'CACHE_REDIS_PORT': 6379,  # default Redis port;
    'CACHE_KEY_PREFIX': 'kevin_'  # Prefix for cache keys;
}

cache = Cache(app, config=cache_config)
api = Api(app)
compress = Compress(app)
# MongoDB configuration
MONGO_URI = os.getenv("MONGODB_URI_PROD")
client = MongoClient(MONGO_URI, maxPoolSize=50, minPoolSize=10)
DB_NAME = "kev"
COLLECTION_NAME = "vulns"
# Connect to MongoDB
#client = MongoClient(MONGO_URI)
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
    if query is None:
        return None

    # Check if the query is an integer, if so, return it without any modifications
    if isinstance(query, int):
        return query

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

MAX_VULNS_PER_PAGE = 100

# Resource for fetching all vulnerabilities
class AllKevVulnerabilitiesResource(Resource):
    def get(self):
        valid_sort_params = {"severity", "date"}  # Changed "dateAdded" to "date"
        valid_order_params = {"asc", "desc"}

        search_query = request.args.get("search", '')
        sort_param = request.args.get("sort", "date")
        order_param = request.args.get("order", "desc")

        # Pagination parameters
        page = int(request.args.get("page", 1))
        per_page = int(request.args.get("per_page", 25))
        if per_page > MAX_VULNS_PER_PAGE:
            per_page = MAX_VULNS_PER_PAGE

        clean_query = sanitize_query(search_query)
        sanitized_sort_param = sanitize_query(sort_param)
        sanitized_order_param = sanitize_query(order_param)

        if sanitized_sort_param not in valid_sort_params or sanitized_order_param not in valid_order_params:
            return {"message": "Invalid sorting parameters"}, 400

        cached_key = f"{clean_query}_{sanitized_sort_param}_{sanitized_order_param}_{page}_{per_page}"
        cached_data = cache.get(cached_key)

        if cached_data is not None:
            vulnerabilities = cached_data
        else:
            skip = (page - 1) * per_page

            if sanitized_sort_param == "date":
                sort_criteria = [('dateAdded', ASCENDING if sanitized_order_param == "asc" else DESCENDING)]  # Sorting by "dateAdded" in MongoDB
                if clean_query:
                    cursor = collection.find({"$text": {"$search": clean_query}}).sort(sort_criteria).skip(skip).limit(per_page)
                else:
                    cursor = collection.find().sort(sort_criteria).skip(skip).limit(per_page)
                vulnerabilities = [serialize_vulnerability(v) for v in cursor]

            else:  # Default to "severity"
                if clean_query:
                    cursor = collection.find({"$text": {"$search": clean_query}}).skip(skip).limit(per_page)
                else:
                    cursor = collection.find().skip(skip).limit(per_page)
                sorted_vulnerabilities = [v for v in cursor if v.get('nvdData') and v['nvdData'][0].get('baseScore') is not None]
                sorted_vulnerabilities.sort(key=lambda v: v['nvdData'][0]['baseScore'], reverse=(sanitized_order_param == "desc"))
                vulnerabilities = [serialize_vulnerability(v) for v in sorted_vulnerabilities]

            cache.set(cached_key, vulnerabilities)

        total_vulns = collection.count_documents({})
        total_pages = math.ceil(total_vulns / per_page)

        return {
            "page": page,
            "per_page": per_page,
            "total_vulns": total_vulns,
            "total_pages": total_pages,
            "vulnerabilities": vulnerabilities
        }


# Resource for fetching recent vulnerabilities
class RecentKevVulnerabilitiesResource(Resource):
    @cache.cached(timeout=100)
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

class RecentVulnerabilitiesByDaysResource(Resource):
    def get(self, query_type):
        days = request.args.get("days")
        page = request.args.get("page", default=1)  # Default to page 1 if not provided
        per_page = request.args.get("per_page", default=25)  # Default to 10 if not provided
        
        if days is None:
            return {"message": "You must provide 'days' parameter"}, 400

        sanitized_days = sanitize_query(days)

        if not isinstance(sanitized_days, int):
            if not sanitized_days.isdigit():
                return {"message": "Invalid value for days parameter"}, 400

            max_days = 14
            if int(sanitized_days) > max_days:
                return {"message": f"Exceeded the maximum limit of {max_days} days"}, 400

        # Sanitize the page parameter
        sanitized_page = sanitize_query(page)

        # Sanitize the page parameter
        sanitized_page = sanitize_query(page)
        
        # Sanitize and limit the per_page parameter
        per_page = request.args.get("per_page", default=10)  # Default to 10 if not provided
        sanitized_per_page = sanitize_query(str(per_page))  # Convert to string before sanitizing
        sanitized_per_page = min(int(sanitized_per_page), 100)  # Limit to maximum 100
        
        cutoff_date = (datetime.utcnow() - timedelta(days=int(sanitized_days))).strftime("%Y-%m-%d")
        field = "pubDateKev" if query_type == "published" else "pubModDateKev"

        start_index = (int(sanitized_page) - 1) * sanitized_per_page

        projection = {
            "_id": 1,
            "pubDateKev": 1,
            "pubModDateKev": 1,
            "namespaces": 1
        }

        recent_vulnerabilities = all_vulns_collection.find(
            {field: {"$gt": cutoff_date}},
            projection
        ).skip(start_index).limit(sanitized_per_page)

        recent_vulnerabilities_list = []
        for vulnerability in recent_vulnerabilities:
            cve_id = vulnerability.get("_id", "")
            namespaces = vulnerability.get("namespaces", {})
            nvd_nist_data = namespaces.get("nvd.nist.gov", {})

            vulnerability_data = {
                "id": cve_id,
                "nvdData": nvd_nist_data
            }
            recent_vulnerabilities_list.append(vulnerability_data)

        total_entries = all_vulns_collection.count_documents({field: {"$gt": cutoff_date}})
        total_pages = math.ceil(total_entries / sanitized_per_page)

        pagination_info = {
            "currentPage": int(sanitized_page),
            "totalPages": total_pages,
            "totalEntries": total_entries,
            "resultsPerPage": sanitized_per_page
        }

        response_data = {
            "pagination": pagination_info,
            "vulnerabilities": recent_vulnerabilities_list
        }

        return response_data
    
@app.route("/vuln/<string:cve_id>/report", methods=["GET"])
@cache.cached(timeout=60)
def vulnerability_report(cve_id):
    # Sanitize the input CVE ID
    sanitized_cve_id = sanitize_query(cve_id)
    vulnerability = all_vulns_collection.find_one({"_id": sanitized_cve_id})
    
    if vulnerability:
        # send the vulnerability data to the reportgen library to generate the report
        report = report_gen(vulnerability)
        return render_template("vulnerability_report.html", report=report)
    else:
        return {"message": "Vulnerability not found"}, 404

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
api.add_resource(RecentVulnerabilitiesByDaysResource, "/vuln/published", endpoint="published", defaults={"query_type": "published"})
api.add_resource(RecentVulnerabilitiesByDaysResource, "/vuln/modified", endpoint="modified", defaults={"query_type": "modified"})

if __name__ == "__main__":
    app.run(debug=False)
