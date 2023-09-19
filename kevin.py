#!/usr/bin/env python3

import re
from utils.database import collection, all_vulns_collection
from urllib.parse import unquote
from flask import Flask, jsonify, render_template, request
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

# Load environment variables using python-dotenv
load_dotenv()
app = Flask(__name__)
api = Api(app)
compress = Compress(app)
init_cache(app)

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
