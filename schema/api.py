# schema/api.py

from utils.database import all_vulns_collection, collection
from utils.cache_manager import cache
from functools import partial
from flask_restful import Resource
from flask import request, Response, json, jsonify, make_response
from pymongo import ASCENDING, DESCENDING
from datetime import datetime, timedelta
import re
from urllib.parse import unquote
import math
from schema.serializers import serialize_vulnerability, serialize_all_vulnerability, nvd_seralizer, mitre_seralizer, serialize_githubpocs

# Load env using python-dotenv
from dotenv import load_dotenv
load_dotenv()

class BaseResource(Resource):
    def handle_error(self, message, status=404):
        response = {"message": message}
        return make_response(jsonify(response), status)

    def make_json_response(self, data, status=200):
        return make_response(jsonify(data), status)

# Pre-compile regex patterns for sanitizing input to improve performance
ALNUM_SPACE_HYPHEN_UNDERSCORE_RE = re.compile(r"[^\w\s-]+", re.UNICODE)
EXTRA_WHITESPACE_RE = re.compile(r"\s+", re.UNICODE)
CVE_RE = re.compile(r"\bcve\b", re.IGNORECASE)

# Function for sanitizing input
def sanitize_query(query):
    if query is None:
        return None
    # Ensure the input is a string
    query = str(query).strip()
    # URL decode iteratively to handle multiple encodings
    while '%' in query:
        decoded_query = unquote(query)
        if decoded_query == query:
            break
        query = decoded_query
    # Remove non-alphanumeric, non-space, non-hyphen, non-underscore characters
    query = ALNUM_SPACE_HYPHEN_UNDERSCORE_RE.sub("", query)  # Use the updated regex
    # Normalize "cve" to "CVE"
    query = CVE_RE.sub("CVE", query)
    # Replace multiple spaces with a single space
    query = EXTRA_WHITESPACE_RE.sub(" ", query).strip()
    return query

# Resource for fectching mitre and nvd data from the cveland via CVE-ID, which is the _id field in the cveland collection
class cveLandResource(BaseResource):
    def get(self, cve_id):
        # Use partial to create a new function that includes the cve_id in the key prefix
        cache_key_func = partial(self.make_cache_key, cve_id=cve_id)
        cached_data = cache.get(cache_key_func())
        if cached_data:
            return self.make_json_response(cached_data)
        sanitized_cve_id = sanitize_query(cve_id)
        vulnerability = all_vulns_collection.find_one({"_id": sanitized_cve_id})
        if not vulnerability:
            return self.handle_error("Vulnerability not found")
        data = serialize_all_vulnerability(vulnerability)
        cache.set(cache_key_func(), data)  # Manually caching the data
        return self.make_json_response(data)

    def make_cache_key(self, cve_id):
        """ Generate a unique cache key including the CVE ID. """
        return f"cve_data_{cve_id}"

# Resource for NVD data from the cveland via CVE-ID, which is the _id field in the cveland collection
class cveNVDResource(BaseResource):
    @cache.cached()
    def get(self, cve_id):
        # Sanitize the input CVE ID
        sanitized_cve_id = sanitize_query(cve_id)
        vulnerability = all_vulns_collection.find_one({"_id": sanitized_cve_id})
        if not vulnerability:
            return self.handle_error("Vulnerability not found")

        data = nvd_seralizer(vulnerability)
        return self.make_json_response(data)

        
# This class defines a resource for fetching Mitre data for a specific CVE-ID from the 'cveland' collection
class cveMitreResource(BaseResource):
    @cache.cached()  # Use caching to improve performance
    def get(self, cve_id):
        # Sanitize the input CVE ID to prevent injection attacks
        sanitized_cve_id = sanitize_query(cve_id)
        # Fetch the vulnerability with the sanitized CVE ID from the 'all_vulns_collection'
        vulnerability = all_vulns_collection.find_one({"_id": sanitized_cve_id})
        if not vulnerability:
            # If the vulnerability is not found, return a 404 error with a message
            return self.handle_error("Vulnerability not found")
        # If the vulnerability is found, serialize it using the 'mitre_seralizer' function
        data = mitre_seralizer(vulnerability)
        # Return the JSON response with the serialized data
        return self.make_json_response(data)
    
# Resource for fetching a specific vulnerability by CVE ID
class VulnerabilityResource(BaseResource):
    def get(self, cve_id):
        # Sanitize the input CVE ID
        sanitized_cve_id = sanitize_query(cve_id)
        # Get the 'references' argument and sanitize it
        references_arg = sanitize_query(request.args.get('references'))
        # Check if the user has requested for PoCs
        if references_arg == 'pocs':
            # Bypass the cache and call the serialize_githubpocs function
            vulnerability = collection.find_one({"cveID": sanitized_cve_id})
            if not vulnerability:
                return self.handle_error("Vulnerability not found")
            data = serialize_githubpocs(vulnerability)
        elif references_arg != "pocs" and references_arg is not None:
            return self.handle_error("Invalid value for references parameter", 400)
        else:
            # Use the cache and call the serialize_vulnerability function
            vulnerability = cache.get(sanitized_cve_id)
            if vulnerability is None:
                vulnerability = collection.find_one({"cveID": sanitized_cve_id})
                if not vulnerability:
                    return self.handle_error("Vulnerability not found")
                cache.set(sanitized_cve_id, vulnerability)
                data = serialize_vulnerability(vulnerability)
            else:
                data = serialize_vulnerability(vulnerability)
        return self.make_json_response(data)

# This class defines a resource for fetching all KEV vulnerabilities
class AllKevVulnerabilitiesResource(BaseResource):
    def get(self):
        try:
            page = int(request.args.get("page", 1))
            per_page = max(1, min(100, int(request.args.get("per_page", 25))))
            sort_param = sanitize_query(request.args.get("sort", "dateAdded"))  # Changed from "date" to "dateAdded"
            order_param = sanitize_query(request.args.get("order", "desc"))
            search_query = sanitize_query(request.args.get("search", ''))

            query = {"$text": {"$search": search_query}} if search_query else {}
            sort_order = DESCENDING if order_param == "desc" else ASCENDING
            sort_criteria = [(sort_param, sort_order)]

            total_vulns = collection.count_documents(query)
            total_pages = math.ceil(total_vulns / per_page)
            cursor = collection.find(query).sort(sort_criteria).skip((page - 1) * per_page).limit(per_page)
            vulnerabilities = [serialize_vulnerability(v) for v in cursor]

            return self.make_json_response({
                "page": page,
                "per_page": per_page,
                "total_vulns": total_vulns,
                "total_pages": total_pages,
                "vulnerabilities": vulnerabilities
            })
        except:
            return self.handle_error("An internal server error occurred", 500)

# Resource for fetching recent vulnerabilities
class RecentKevVulnerabilitiesResource(BaseResource):
    @cache.cached(timeout=5)
    def get(self):
        # Get the 'days' parameter from the query string
        days = request.args.get("days", type=int)
        # Validate the 'days' parameter
        if days is None or days < 0:
            return self.handle_error("Invalid value for days", 400)
        # Calculate the cutoff date based on the 'days' parameter
        cutoff_date = datetime.utcnow() - timedelta(days=days)
        recent_vulnerabilities = []
        # Fetch all vulnerabilities from the collection
        cursor = collection.find()
        # Iterate over the vulnerabilities
        for vulnerability in cursor:
            date_added_str = vulnerability.get("dateAdded")
            try:
                # Convert the date from string to datetime
                date_added = datetime.strptime(date_added_str, "%Y-%m-%d")
                
                # Check if the vulnerability was added within the cutoff date
                if date_added >= cutoff_date:
                    # Serialize the vulnerability and add it to the list
                    recent_vulnerabilities.append(
                        serialize_vulnerability(vulnerability)
                    )
            except ValueError:
                # Ignore vulnerabilities with invalid date formats
                continue
        # Return the JSON response with the serialized data
        return self.make_json_response(recent_vulnerabilities)

class RecentVulnerabilitiesByDaysResource(BaseResource):
    def get(self, query_type):
        # Get the query parameters
        days = request.args.get("days")
        page = request.args.get("page", default=1, type=int)  # Default to page 1 if not provided
        per_page = request.args.get("per_page", default=25, type=int)  # Default to 25 if not provided
        # Check if 'days' parameter is provided
        if days is None:
            return self.handle_error("You must provide 'days' parameter", 400)
        # Sanitize the 'days' parameter
        days = sanitize_query(days)
        if not days.isdigit() or int(days) < 0:
            return self.handle_error("Invalid value for days parameter. Please provide a non-negative integer no greater than 14.", 400)
        if int(days) > 14:  # Limit the 'days' parameter to a maximum of 14
            return self.handle_error("Exceeded the maximum limit of 14 days", 400)
        cutoff_date = (datetime.utcnow() - timedelta(days=int(days))).strftime("%Y-%m-%d")
        field = "pubDateKev" if query_type == "published" else "pubModDateKev"
        # Define the fields to return in the response
        projection = {"_id": 1, "pubDateKev": 1, "pubModDateKev": 1, "namespaces": 1}
        # Query the database for recent vulnerabilities
        recent_vulnerabilities = all_vulns_collection.find(
            {field: {"$gt": cutoff_date}},
            projection
        ).skip((page - 1) * per_page).limit(per_page)
        recent_vulnerabilities_list = [
            {"id": v.get("_id", ""), "nvdData": v.get("namespaces", {}).get("nvd.nist.gov", {})}
            for v in recent_vulnerabilities
        ]
        # Calculate the total number of entries and pages
        total_entries = all_vulns_collection.count_documents({field: {"$gt": cutoff_date}})
        total_pages = math.ceil(total_entries / per_page)
        # Prepare the pagination info and response data
        pagination_info = {
            "currentPage": page,
            "totalPages": total_pages,
            "totalEntries": total_entries,
            "resultsPerPage": per_page
        }
        response_data = {
            "pagination": pagination_info,
            "vulnerabilities": recent_vulnerabilities_list
        }
        return self.make_json_response(response_data)

    