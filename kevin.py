#!/usr/bin/env python3

# Standard Library Imports
import os
import re
from urllib.parse import unquote

# Third-Party Library Imports
from dotenv import load_dotenv
from flask import Flask, jsonify, render_template, request, send_from_directory
from flask_restful import Api
from flask_compress import Compress
from gevent.pywsgi import WSGIServer

# Project-Specific Imports
from utils.database import collection, all_vulns_collection
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
from schema.serializers import serialize_vulnerability, serialize_all_vulnerability


# Create a cache key for openai routes based on the query parameters
def cve_cache_key(*args, **kwargs):
    path = request.path
    args = str(hash(frozenset(request.args.items())))
    return path + args

# Load environment variables using python-dotenv
load_dotenv()

# Initialize the Flask app and the Flask-RESTful API
app = Flask(__name__)
api = Api(app)

# Enable GZIP compression for all routes
compress = Compress(app)

# Initialize the Flask-Caching extension
init_cache(app)

# Function for sanitizing input to prevent SQL injection attacks and such
def sanitize_query(query):
    # Convert the query to a string, in case it's an integer
    query = str(query)
    # If the query is 'None', return None
    if query == 'None':
        return None
    # Continuously decode the query until it can't be decoded any further to ensure we're not vulnerable to double URL encoding
    while '%' in query:
        decoded_query = unquote(query)
        # If decoding doesn't change the query, break the loop
        if decoded_query == query:
            break
        else:
            # If decoding changes the query, update the query with the decoded version and continue the loop
            query = decoded_query
    # Allow alphanumeric characters, spaces, and hyphens in the query, remove all other characters
    query = re.sub(r"[^a-zA-Z0-9\s-]", "", query)
    # Replace 'cve' with 'CVE' in the query, ignoring case
    query = re.sub(r'\bcve\b', 'CVE', query, flags=re.IGNORECASE)
    # Remove extra whitespace from the start and end of the query
    query = query.strip()
    # Replace multiple consecutive spaces in the query with a single space
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

# Route for the metrics page ("/get_metrics")
@app.route('/get_metrics')
@cache.cached(timeout=1800) # 30 minute cache for the metrics route.
def get_metrics():
    # Count the number of documents in the 'collection' (KEVs)
    kevs_count = collection.count_documents({})
    # Count the number of documents in the 'all_vulns_collection' (CVEs)
    cves_count = all_vulns_collection.count_documents({})
    # Create a dictionary to hold the metrics
    metrics = {
        'cves_count': cves_count, # Number of CVEs
        'kevs_count': kevs_count, # Number of KEVs
    }
    # Return the metrics as a JSON response
    return jsonify(metrics)

# Route to check if a specific CVE ID exists in the KEV database collection
# Example usage: /kev/exists?cve=CVE-2021-1234
@app.route("/kev/exists", methods=["GET"])
@cache.cached(timeout=15, key_prefix='cve_exist', query_string=True) # 15 second cache for the cve_exist route.
def cve_exist():
    # Extract the 'cve' query parameter from the URL
    cve_id = request.args.get('cve')
    # If the 'cve' query parameter is not provided, return an error message
    if not cve_id:
        return jsonify({"message": "CVE ID is required as a query parameter."}), 400
    # Sanitize the input CVE ID to prevent SQL injection attacks
    sanitized_cve_id = sanitize_query(cve_id)
    # Use the sanitized CVE ID to fetch the corresponding vulnerability from the database
    vulnerability = collection.find_one({"cveID": sanitized_cve_id})
    # If the vulnerability is found, return a JSON response indicating that the CVE ID exists in the KEV database
    if vulnerability:
        return jsonify({"In_KEV": True})
    # If the vulnerability is not found, return a JSON response indicating that the CVE ID does not exist in the KEV database
    else:
        return jsonify({"In_KEV": False})

# Route for generating a report for a specific vulnerability
@app.route("/vuln/<string:cve_id>/report", methods=["GET"])
@cache.cached() # Use the default 10 minute cache for the report route.
def vulnerability_report(cve_id):
    # Sanitize the input CVE ID to prevent SQL injection attacks
    sanitized_cve_id = sanitize_query(cve_id)
    # Use the sanitized CVE ID to fetch the corresponding vulnerability from the database
    vulnerability = all_vulns_collection.find_one({"_id": sanitized_cve_id})
    # If the vulnerability is found
    if vulnerability:
        # Send the vulnerability data to the reportgen library to generate the report
        report = report_gen(vulnerability)
        # Render the vulnerability report template with the generated report
        return render_template("vulnerability_report.html", report=report)
    # If the vulnerability is not found, return an error message
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

# OpenAI route for a specific vulnerability with cve parameter
@app.route("/openai/kev")
@cache.cached(timeout=10, key_prefix=cve_cache_key) # 10 second cache for the openai route.
def openai_kev():
    # Extract the 'cve' query parameter from the URL
    cve_id = request.args.get('cve')
    # If the 'cve' query parameter is not provided, return an error message
    if not cve_id:
        return {"message": "CVE ID is required as a query parameter."}, 400
    # Sanitize the input CVE ID to prevent SQL injection attacks
    sanitized_cve_id = sanitize_query(cve_id)
    # Use the sanitized CVE ID to fetch the corresponding vulnerability from the database
    vulnerability = collection.find_one({"cveID": sanitized_cve_id})
    # If the vulnerability is found, serialize it and return it as a JSON response
    if vulnerability:
        data = serialize_vulnerability(vulnerability)
        response = jsonify(data)
        # Set the content type of the response to 'application/json'
        response.content_type = "application/json"
        return response
    # If the vulnerability is not found, return an error message
    else:
        return {"message": "Vulnerability not found"}, 404
    
# OpenAI route for all vulnerabilities with cve parameter
@app.route("/openai/vuln")
@cache.cached(timeout=10, key_prefix=cve_cache_key) # 10 second cache for the openai route.
def openai_vuln():
    # Extract the 'cve' query parameter from the URL
    cve_id = request.args.get('cve')
    # If the 'cve' query parameter is not provided, return an error message
    if not cve_id:
        return {"message": "CVE ID is required as a query parameter."}, 400
    # Sanitize the input CVE ID to prevent SQL injection attacks
    sanitized_cve_id = sanitize_query(cve_id)
    # Use the sanitized CVE ID to fetch the corresponding vulnerability from the database
    vulnerability = all_vulns_collection.find_one({"_id": sanitized_cve_id})
    # If the vulnerability is found, serialize it and return it as a JSON response
    if vulnerability:
        data = serialize_all_vulnerability(vulnerability)
        response = jsonify(data)
        # Set the content type of the response to 'application/json'
        response.content_type = "application/json"
        return response
    # If the vulnerability is not found, return an error message
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
    # Start the Flask app with Gevent WSGI server
    http_server = WSGIServer(('0.0.0.0', 5000), app)
    http_server.serve_forever()
