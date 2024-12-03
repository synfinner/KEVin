#!/usr/bin/env python3

# Standard Library Imports
import os

# Third-Party Library Imports
from dotenv import load_dotenv
from flask import Flask, jsonify, render_template, request, send_from_directory, make_response, Response
from flask_restful import Api
from flask_compress import Compress
from gevent.pywsgi import WSGIServer
from gevent import spawn, joinall

# Project-Specific Imports
from utils.database import collection, all_vulns_collection
from utils.cache_manager import kev_cache as cache 
from utils.sanitizer import sanitize_query
from utils.rss_feed import create_rss_feed
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

# Route for the root endpoint ("/")
@app.route("/")
@cache(timeout=1800) # 30 minute cache for the main route.
def index():
    return render_template("index.html")

@app.route('/robots.txt')
# 1 hour cache.
@cache(timeout=3600)
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
@cache(timeout=3600)
def serve_privacy_policy():
    file_path = os.path.join(app.static_folder, 'privacy.html')
    with open(file_path, 'r') as file:
        file_content = file.read()
    response = make_response(file_content)
    response.headers['Content-Type'] = 'text/html'
    return response

@app.route('/about')
# 1 hour cache.
@cache(timeout=3600)
def serve_about_page():
    file_path = os.path.join(app.static_folder, 'about.html')
    with open(file_path, 'r') as file:
        file_content = file.read()
    response = make_response(file_content)
    response.headers['Content-Type'] = 'text/html'
    return response

@app.route('/donate')
# 1 hour cache.
@cache(timeout=3600)
def serve_donate():
    file_path = os.path.join(app.static_folder, 'donate.html')
    with open(file_path, 'r') as file:
        file_content = file.read()
    response = make_response(file_content)
    response.headers['Content-Type'] = 'text/html'
    return response

# Route for example page ("/example")
@app.route("/examples")
@cache(timeout=3600) # 1 hour cache for the example page.
def example():
    return render_template("example.html")

@app.route("/agreement")
@cache(timeout=3600)  # 1 hour cache for the agreement page.
def user_agreement():
    # Read the file content into memory
    file_path = os.path.join(app.static_folder, 'agreement.html')
    with open(file_path, 'r') as file:
        file_content = file.read()
    
    # Create a response object with the file content
    response = make_response(file_content)
    response.headers['Content-Type'] = 'text/html'
    return response

@app.route("/rss")
@cache(timeout=1800, key_prefix='rss_feed')  # 30 minute cache for the RSS feed.
def rss_feed():
    # Fetch recent KEV Entries from the MongoDB collection
    recent_entries = collection.find().sort("dateAdded", -1).limit(12)
    # Create an RSS feed from the recent KEV Entries
    rss_feed = create_rss_feed(recent_entries)
    return Response(rss_feed, mimetype='application/rss+xml')


# Route for the metrics page ("/get_metrics")
@app.route('/get_metrics')
@cache(timeout=1800) # 30 minute cache for the metrics route.
def get_metrics():
    """
    Retrieve metrics for the KEV and CVE databases.

    This function counts the number of KEVs and CVEs in their respective
    collections using Gevent for concurrent execution. It returns the
    counts as a JSON response.

    Returns:
        Response: A JSON object containing the counts of CVEs and KEVs.
    """
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
@cache(timeout=15, key_prefix='cve_exist', query_string=True) # 15 second cache for the cve_exist route.
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
@cache() # Use the default 10 minute cache for the report route.
def vulnerability_report(cve_id):
    """
    Generate a report for a specific vulnerability identified by its CVE ID.

    This function sanitizes the input CVE ID to prevent SQL injection attacks,
    retrieves the corresponding vulnerability from the database, and generates
    a report using the reportgen library. If the vulnerability is found, it
    renders the vulnerability report template with the generated report. If
    the vulnerability is not found, it returns a 404 error message.

    Parameters:
    - cve_id (str): The CVE ID of the vulnerability for which the report is generated.

    Returns:
    Response: Renders the vulnerability report template if the vulnerability is found,
              or returns a 404 error message if the vulnerability is not found.
    """
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
@cache(timeout=10, key_prefix=cve_cache_key) # 10 second cache for the openai route.
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
@cache(timeout=10, key_prefix=cve_cache_key) # 10 second cache for the openai route.
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

# Define the resource routes for the KEVin API.
# Each tuple contains a resource class and its corresponding URL endpoint.
resources = [
    (VulnerabilityResource, "/kev/<string:cve_id>", "kev_vulnerability_resource"),  # Unique endpoint for /kev
    (VulnerabilityResource, "/api/kev/<string:cve_id>", "api_kev_vulnerability_resource"),  # Unique endpoint for /api/kev
    (AllKevVulnerabilitiesResource, "/kev", "all_kevs_resource"),  # Unique endpoint for /kev
    (AllKevVulnerabilitiesResource, "/api/kev", "api_all_kevs_resource"),  # Unique endpoint for /api/kev
    (RecentKevVulnerabilitiesResource, "/kev/recent", "recent_kevs_resource"),  # Unique endpoint for /kev/recent
    (RecentKevVulnerabilitiesResource, "/api/kev/recent", "api_recent_kevs_resource"),  # Unique endpoint for /api/kev/recent
    (cveLandResource, "/vuln/<string:cve_id>", "cve_land_resource"),  # Unique endpoint for /vuln
    (cveLandResource, "/api/vuln/<string:cve_id>", "api_cve_land_resource"),  # Unique endpoint for /api/vuln
    (cveNVDResource, "/vuln/<string:cve_id>/nvd", "cve_nvd_resource"),  # Unique endpoint for /vuln/nvd
    (cveNVDResource, "/api/vuln/<string:cve_id>/nvd", "api_cve_nvd_resource"),  # Unique endpoint for /api/vuln/nvd
    (cveMitreResource, "/vuln/<string:cve_id>/mitre", "cve_mitre_resource"),  # Unique endpoint for /vuln/mitre
    (cveMitreResource, "/api/vuln/<string:cve_id>/mitre", "api_cve_mitre_resource"),  # Unique endpoint for /api/vuln/mitre
    (RecentVulnerabilitiesByDaysResource, "/vuln/published", {"query_type": "published"}, "recent_published_vulns_resource"),  # Unique endpoint for /vuln/published
    (RecentVulnerabilitiesByDaysResource, "/api/vuln/published", {"query_type": "published"}, "api_recent_published_vulns_resource"),  # Unique endpoint for /api/vuln/published
    (RecentVulnerabilitiesByDaysResource, "/vuln/modified", {"query_type": "modified"}, "recent_modified_vulns_resource"),  # Unique endpoint for /vuln/modified
    (RecentVulnerabilitiesByDaysResource, "/api/vuln/modified", {"query_type": "modified"}, "api_recent_modified_vulns_resource"),  # Unique endpoint for /api/vuln/modified
]

# Add resources to the API with unique endpoints
for resource in resources:
    if len(resource) == 3:  # Case for resources with just the resource class, URL, and endpoint
        api.add_resource(resource[0], resource[1], strict_slashes=False, endpoint=resource[2])
    elif len(resource) == 4:  # Case for resources with additional kwargs (e.g., query_type)
        api.add_resource(resource[0], resource[1], strict_slashes=False, resource_class_kwargs=resource[2], endpoint=resource[3])
# Check if the script is being run directly
if __name__ == "__main__":
    # Start the Flask application using the Gevent WSGI server
    http_server = WSGIServer(('0.0.0.0', 5000), app)
    # Keep the server running indefinitely to handle incoming requests
    http_server.serve_forever()
