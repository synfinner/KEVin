#!/usr/bin/env python3

import re
import os
from utils.database import collection, all_vulns_collection
from urllib.parse import unquote
from flask import Flask, jsonify, render_template, request, send_from_directory
from flask_restful import Api, Resource
from flask_compress import Compress
from dotenv import load_dotenv
from utils.cache_manager import cache, init_cache
from modules.reportgen import report_gen
from schema.api import (
    cveLandResource, 
    cveNVDResource, 
    cveMitreResource, 
    VulnerabilityResource, 
    AllKevVulnerabilitiesResource, 
    RecentKevVulnerabilitiesResource, 
    RecentVulnerabilitiesByDaysResource
)
from schema.serializers import serialize_vulnerability,serialize_all_vulnerability


# Create a cache key for openai routes based on the query parameters
def cve_cache_key(*args, **kwargs):
    path = request.path
    args = str(hash(frozenset(request.args.items())))
    return path + args

# Load environment variables using python-dotenv
load_dotenv()
app = Flask(__name__)
api = Api(app)
compress = Compress(app)
init_cache(app)

#Function for sanitizing input
def sanitize_query(query):
    # Convert the query to a string, in case it's an integer
    query = str(query)
    if query == 'None':
        return None
    # URL decode the query
    query = unquote(query)
    # Allow alphanumeric characters, spaces, and hyphens
    query = re.sub(r"[^a-zA-Z0-9\s-]", "", query)
    # Remove extra whitespace from query
    query = query.strip()
    query = re.sub(r"\s+", " ", query)
    # Finally, return the sanitized query
    return query

# Route for the root endpoint ("/")
@app.route("/")
@cache.cached(timeout=1800) # 30 minute cache for the main route.
def index():
    return render_template("index.html")

@app.route('/robots.txt')
def serve_robots_txt():
    return send_from_directory(app.static_folder, 'robots.txt')

# Route for example page ("/example")
@app.route("/examples")
@cache.cached(timeout=3600) # 1 hour cache for the example page.
def example():
    return render_template("example.html")

@app.route('/get_metrics')
@cache.cached(timeout=1800) # 30 minute cache for the metrics route.
def get_metrics():
    kevs_count = collection.count_documents({})
    cves_count = all_vulns_collection.count_documents({})

    metrics = {
        'cves_count': cves_count,
        'kevs_count': kevs_count,
    }

    return jsonify(metrics)
    
@app.route("/vuln/<string:cve_id>/report", methods=["GET"])
@cache.cached() # use the default 10 minute cache for the report route.
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

# OpenAI route

@app.route("/openai/kev")
@cache.cached(timeout=10, key_prefix=cve_cache_key) # 10 second cache for the openai route.
def openai_kev():
    # Extract the 'cve' query parameter from the URL
    cve_id = request.args.get('cve')
    if not cve_id:
        return {"message": "CVE ID is required as a query parameter."}, 400

    # Sanitize the input CVE ID as done in the VulnerabilityResource class
    sanitized_cve_id = sanitize_query(cve_id)
    
    # Reuse the existing logic to fetch the vulnerability
    vulnerability = collection.find_one({"cveID": sanitized_cve_id})
    if vulnerability:
        data = serialize_vulnerability(vulnerability)
        response = jsonify(data)
        response.content_type = "application/json"
        return response
    else:
        return {"message": "Vulnerability not found"}, 404
    
# OpenAI route for all vulnerabilities with cve parameter
@app.route("/openai/vuln")
@cache.cached(timeout=10, key_prefix=cve_cache_key) # 10 second cache for the openai route.
def openai_vuln():
    # Extract the 'cve' query parameter from the URL
    cve_id = request.args.get('cve')
    if not cve_id:
        return {"message": "CVE ID is required as a query parameter."}, 400

    # Sanitize the input CVE ID as done in the VulnerabilityResource class
    sanitized_cve_id = sanitize_query(cve_id)
    
    # Reuse the existing logic to fetch the vulnerability
    vulnerability = all_vulns_collection.find_one({"_id": sanitized_cve_id})
    if vulnerability:
        data = serialize_all_vulnerability(vulnerability)
        response = jsonify(data)
        response.content_type = "application/json"
        return response
    else:
        return {"message": "Vulnerability not found"}, 404

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
