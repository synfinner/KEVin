#!/usr/bin/env python3

# Standard Library Imports
import os
import re
from urllib.parse import unquote

# Third-Party Library Imports
from dotenv import load_dotenv
from flask import Flask, jsonify, render_template, request, send_from_directory, make_response
from flask_restful import Api
from flask_compress import Compress
from gevent.pywsgi import WSGIServer
from gevent import spawn, joinall

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
    """
    Sanitize the input query to prevent malicious input.

    This function checks and sanitizes the provided query string by:
    - Returning None if the query is None or exceeds a specified length.
    - Iteratively URL decoding the query to handle encoded characters.
    - Whitelisting allowed characters (alphanumeric, spaces, hyphens, underscores).
    - Normalizing occurrences of "cve" to "CVE".
    - Replacing multiple spaces with a single space.
    - Checking for potential SQL injection patterns and returning None for suspicious queries.

    Parameters:
    query (str): The input query string to sanitize.

    Returns:
    str or None: The sanitized query string if valid, or None if the input is invalid or suspicious.
    """
    # Check if the query is None
    if query is None:
        return None
    
    query = str(query).strip()
    # Length check
    if len(query) > 50:
        return None
    
    # URL decode iteratively
    while '%' in query:
        decoded_query = unquote(query)
        if decoded_query == query:
            break
        query = decoded_query
    
    # Whitelist allowed characters (alphanumeric, spaces, hyphens, underscores)
    query = re.sub(r"[^\w\s-]", "", query)
    
    # Normalize "cve" to "CVE"
    query = re.sub(r'\bcve\b', 'CVE', query, flags=re.IGNORECASE)
    
    # Replace multiple spaces with a single space
    query = re.sub(r"\s+", " ", query).strip()
    
    # Check for potential SQL injection patterns (without logging)
    if re.search(r"(\b(SELECT|INSERT|UPDATE|DELETE|DROP|;|--)\b)", query, re.IGNORECASE):
        return None  # Return None for suspicious queries
    
    return query

# Route for the root endpoint ("/")
@app.route("/")
@cache.cached(timeout=1800) # 30 minute cache for the main route.
def index():
    return render_template("index.html")

@app.route('/robots.txt')
# 1 hour cache.
@cache.cached(timeout=3600)
def serve_robots_txt():
    file_path = os.path.join(app.static_folder, 'robots.txt')
    with open(file_path, 'r') as file:
        file_content = file.read()
    response = make_response(file_content)
    response.headers['Content-Type'] = 'text/plain'
    return response

@app.route('/graph')
def serve_graph_html():
    file_path = os.path.join(app.static_folder, 'cve_visualization.html')
    with open(file_path, 'r') as file:
        file_content = file.read()
    response = make_response(file_content)
    response.headers['Content-Type'] = 'text/html'
    return response

@app.route('/viz')
#@cache.cached(timeout=3600)
def serve_viz_html():
    file_path = os.path.join(app.static_folder, 'viz.html')
    with open(file_path, 'r') as file:
        file_content = file.read()
    response = make_response(file_content)
    response.headers['Content-Type'] = 'text/html'
    return response

@app.route('/privacy-policy')
# 1 hour cache.
@cache.cached(timeout=3600)
def serve_privacy_policy():
    file_path = os.path.join(app.static_folder, 'privacy.html')
    with open(file_path, 'r') as file:
        file_content = file.read()
    response = make_response(file_content)
    response.headers['Content-Type'] = 'text/html'
    return response

@app.route('/about')
# 1 hour cache.
@cache.cached(timeout=3600)
def serve_about_page():
    file_path = os.path.join(app.static_folder, 'about.html')
    with open(file_path, 'r') as file:
        file_content = file.read()
    response = make_response(file_content)
    response.headers['Content-Type'] = 'text/html'
    return response

@app.route('/donate')
# 1 hour cache.
@cache.cached(timeout=3600)
def serve_donate():
    file_path = os.path.join(app.static_folder, 'donate.html')
    with open(file_path, 'r') as file:
        file_content = file.read()
    response = make_response(file_content)
    response.headers['Content-Type'] = 'text/html'
    return response

# Route for example page ("/example")
@app.route("/examples")
@cache.cached(timeout=3600) # 1 hour cache for the example page.
def example():
    return render_template("example.html")

@app.route("/agreement")
@cache.cached(timeout=3600)  # 1 hour cache for the agreement page.
def user_agreement():
    # Read the file content into memory
    file_path = os.path.join(app.static_folder, 'agreement.html')
    with open(file_path, 'r') as file:
        file_content = file.read()
    
    # Create a response object with the file content
    response = make_response(file_content)
    response.headers['Content-Type'] = 'text/html'
    return response

# Route for the metrics page ("/get_metrics")
@app.route('/get_metrics')
@cache.cached(timeout=1800) # 30 minute cache for the metrics route.
def get_metrics():
    # Use Gevent to spawn greenlets for counting documents
    def count_kevs():
        return collection.count_documents({})

    def count_cves():
        return all_vulns_collection.count_documents({})

    # Spawn the greenlets
    kevs_greenlet = spawn(count_kevs)
    cves_greenlet = spawn(count_cves)

    # Wait for the greenlets to finish
    joinall([kevs_greenlet, cves_greenlet])

    # Get the results from the greenlets
    kevs_count = kevs_greenlet.value
    cves_count = cves_greenlet.value

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
    """
    Check if a specific CVE ID exists in the KEV database.

    This function extracts the 'cve' query parameter from the request URL,
    sanitizes it to prevent SQL injection attacks, and checks the database
    for the existence of the corresponding vulnerability. It returns a JSON
    response indicating whether the CVE ID exists in the KEV database.

    Query Parameters:
    - cve (str): The CVE ID to check for existence in the KEV database.

    Returns:
    Response: A JSON response indicating whether the CVE ID exists in the
              KEV database. Returns a 400 error if the CVE ID is not provided.
    """
    # Extract the 'cve' query parameter from the URL
    cve_id = request.args.get('cve')
    # If the 'cve' query parameter is not provided, return an error message
    if not cve_id:
        return jsonify({"message": "CVE ID is required as a query parameter."}), 400
    # Sanitize the input CVE ID to prevent SQL injection attacks
    sanitized_cve_id = sanitize_query(cve_id)

    # Use Gevent to spawn a greenlet for the database query
    def fetch_vulnerability():
        return collection.find_one({"cveID": sanitized_cve_id})

    # Spawn the greenlet
    greenlet = spawn(fetch_vulnerability)
    # Wait for the greenlet to finish
    joinall([greenlet])

    # Get the result from the greenlet
    vulnerability = greenlet.value

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
    """
    Retrieve KEV vulnerability data for a specific CVE ID from the database.

    This function extracts the 'cve' query parameter from the request URL,
    sanitizes it to prevent SQL injection attacks, and fetches the corresponding
    vulnerability from the database. If the vulnerability is found, it serializes
    the data and returns it as a JSON response. If the CVE ID is not provided
    or the vulnerability is not found, it returns an appropriate error message.

    Query Parameters:
    - cve (str): The CVE ID of the vulnerability to retrieve.

    Returns:
    Response: A JSON response containing the serialized KEV vulnerability data
              or an error message if the CVE ID is missing or the vulnerability
              is not found.
    """
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
    """
    Retrieve vulnerability data for a specific CVE ID from the database.

    This function extracts the 'cve' query parameter from the request URL,
    sanitizes it to prevent SQL injection attacks, and fetches the corresponding
    vulnerability from the database. If the vulnerability is found, it serializes
    the data and returns it as a JSON response. If the CVE ID is not provided
    or the vulnerability is not found, it returns an appropriate error message.

    Query Parameters:
    - cve (str): The CVE ID of the vulnerability to retrieve.

    Returns:
    Response: A JSON response containing the serialized vulnerability data
              or an error message if the CVE ID is missing or the vulnerability
              is not found.
    """
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
resources = [
    (VulnerabilityResource, "/kev/<string:cve_id>"),
    (AllKevVulnerabilitiesResource, "/kev"),
    (RecentKevVulnerabilitiesResource, "/kev/recent"),
    (cveLandResource, "/vuln/<string:cve_id>"),
    (cveNVDResource, "/vuln/<string:cve_id>/nvd"),
    (cveMitreResource, "/vuln/<string:cve_id>/mitre"),
    (RecentVulnerabilitiesByDaysResource, "/vuln/published", {"query_type": "published"}),
    (RecentVulnerabilitiesByDaysResource, "/vuln/modified", {"query_type": "modified"}),
]

for resource in resources:
    if len(resource) == 2:
        api.add_resource(resource[0], resource[1], strict_slashes=False)
    else:
        # Use resource_class_kwargs to pass query_type
        api.add_resource(resource[0], resource[1], strict_slashes=False, resource_class_kwargs=resource[2], endpoint=f"{resource[0].__name__}_{resource[1].replace('/', '_')}")

if __name__ == "__main__":
    # Start the Flask app with Gevent WSGI server
    http_server = WSGIServer(('0.0.0.0', 5000), app)
    http_server.serve_forever()
