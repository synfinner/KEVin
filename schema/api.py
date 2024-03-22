# schema/api.py

from utils.database import all_vulns_collection, collection
from utils.cache_manager import cache
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

# Add the function and class definitions here...
#Function for sanitizing input
def sanitize_query(query):
    # Convert the query to a string, in case it's an integer
    query = str(query)
    if query == 'None':
        return None
    # Continuously decode the query until it can't be decoded any further to ensure we're not vulnerable to double URL encoding
    while '%' in query:
        decoded_query = unquote(query)
        if decoded_query == query:
            break
        else:
            query = decoded_query
    # Allow alphanumeric characters, spaces, and hyphens
    query = re.sub(r"[^a-zA-Z0-9\s-]", "", query)
    query = re.sub(r'\bcve\b', 'CVE', query, flags=re.IGNORECASE)
    # Remove extra whitespace from query
    query = query.strip()
    query = re.sub(r"\s+", " ", query)
    # Finally, return the sanitized query
    return query

# Resource for fectching mitre and nvd data from the cveland via CVE-ID, which is the _id field in the cveland collection
class cveLandResource(Resource):
    @cache.cached()
    def get(self, cve_id):
        # Sanitize the input CVE ID
        sanitized_cve_id = sanitize_query(cve_id)
        vulnerability = all_vulns_collection.find_one({"_id": sanitized_cve_id})
        if vulnerability:
            data = serialize_all_vulnerability(vulnerability)
            #return serialize_all_vulnerability(vulnerability)
        else:
            return {"message": "Vulnerability not found"}, 404
        response = Response(json.dumps(data), content_type="application/json")
        return response

# Resource for NVD data from the cveland via CVE-ID, which is the _id field in the cveland collection
class cveNVDResource(Resource):
    @cache.cached()
    def get(self, cve_id):
        # Sanitize the input CVE ID
        sanitized_cve_id = sanitize_query(cve_id)
        vulnerability = all_vulns_collection.find_one({"_id": sanitized_cve_id})
        if vulnerability:
            data = nvd_seralizer(vulnerability)
            #return nvd_seralizer(vulnerability)
        else:
            return {"message": "Vulnerability not found"}, 404
        response = Response(json.dumps(data), content_type="application/json")
        return response
        
# This class defines a resource for fetching Mitre data for a specific CVE-ID from the 'cveland' collection
class cveMitreResource(Resource):
    # The GET method for this resource
    @cache.cached()  # Use caching to improve performance
    def get(self, cve_id):
        # Sanitize the input CVE ID to prevent injection attacks
        sanitized_cve_id = sanitize_query(cve_id)
        # Fetch the vulnerability with the sanitized CVE ID from the 'all_vulns_collection'
        vulnerability = all_vulns_collection.find_one({"_id": sanitized_cve_id})
        if vulnerability:
            # If the vulnerability is found, serialize it using the 'mitre_seralizer' function
            data = mitre_seralizer(vulnerability)
        else:
            # If the vulnerability is not found, return a 404 error with a message
            return {"message": "Vulnerability not found"}, 404
        # Create a response with the serialized data, and set the content type to "application/json"
        response = Response(json.dumps(data), content_type="application/json")
        # Return the response
        return response
    
# Resource for fetching a specific vulnerability by CVE ID
class VulnerabilityResource(Resource):
    def get(self, cve_id):
        # Sanitize the input CVE ID
        sanitized_cve_id = sanitize_query(cve_id)

        # Get the 'references' argument and sanitize it
        references_arg = sanitize_query(request.args.get('references'))

        # Check if the user has requested for PoCs
        if references_arg == 'pocs':
            # Bypass the cache and call the serialize_githubpocs function
            vulnerability = collection.find_one({"cveID": sanitized_cve_id})
            if vulnerability:
                data = serialize_githubpocs(vulnerability)
            else:
                return {"message": "Vulnerability not found"}, 404
        elif references_arg != "pocs" and references_arg is not None:
            return {"message": "Invalid value for references parameter"}, 400
        else:
            # Use the cache and call the serialize_vulnerability function
            vulnerability = cache.get(sanitized_cve_id)
            if vulnerability is None:
                vulnerability = collection.find_one({"cveID": sanitized_cve_id})
                if vulnerability:
                    cache.set(sanitized_cve_id, vulnerability)
                    data = serialize_vulnerability(vulnerability)
                else:
                    return {"message": "Vulnerability not found"}, 404
            else:
                data = serialize_vulnerability(vulnerability)

        response = Response(json.dumps(data), content_type="application/json")
        return response

MAX_VULNS_PER_PAGE = 100

# This class defines a resource for fetching all KEV vulnerabilities
class AllKevVulnerabilitiesResource(Resource):
    # The GET method for this resource
    def get(self):
        # Define valid parameters for sorting and ordering
        valid_sort_params = {"severity", "date"}
        valid_order_params = {"asc", "desc"}
        # Extract parameters from the request
        search_query = request.args.get("search", '')
        sort_param = request.args.get("sort", "date")
        order_param = request.args.get("order", "desc")
        filter_param = request.args.get("filter", '')
        page = int(request.args.get("page", 1))
        per_page = int(request.args.get("per_page", 25))
        # Sanitize the parameters to prevent SQL injection attacks
        clean_query = sanitize_query(search_query)
        sanitized_sort_param = sanitize_query(sort_param)
        sanitized_order_param = sanitize_query(order_param)
        sanitized_filter_param = sanitize_query(filter_param)
        # Build the MongoDB query
        query = {"$text": {"$search": clean_query}} if clean_query else {}
        if sanitized_filter_param.lower() == 'ransomware':
            query['knownRansomwareCampaignUse'] = 'Known'
        # Count the total number of vulnerabilities matching the query
        total_vulns = collection.count_documents(query)
        total_pages = math.ceil(total_vulns / per_page)
        # Build the cache key
        cached_key = f"{clean_query}_{sanitized_sort_param}_{sanitized_order_param}_{page}_{per_page}_{sanitized_filter_param}"
        cached_data = cache.get(cached_key)
        vulnerabilities = []
        # If the data is in the cache, use it
        if cached_data is not None:
            vulnerabilities = cached_data
        else:
            # If the data is not in the cache, fetch it from the database
            skip = (page - 1) * per_page
            if sanitized_sort_param == "date":
                sort_criteria = [('dateAdded', ASCENDING if sanitized_order_param == "asc" else DESCENDING)]
                cursor = collection.find(query).sort(sort_criteria).skip(skip).limit(per_page)
                vulnerabilities = [serialize_vulnerability(v) for v in cursor]
            else:  # Default to "severity"
                cursor = collection.find(query).skip(skip).limit(per_page)
                sorted_vulnerabilities = [v for v in cursor if v.get('nvdData') and v['nvdData'][0].get('baseScore') is not None]
                sorted_vulnerabilities.sort(key=lambda v: v['nvdData'][0]['baseScore'], reverse=(sanitized_order_param == "desc"))
                vulnerabilities = [serialize_vulnerability(v) for v in sorted_vulnerabilities]
            # Store the fetched data in the cache
            cache.set(cached_key, vulnerabilities)
        # Build the response data
        data = {
            "page": page,
            "per_page": per_page,
            "total_vulns": total_vulns,
            "total_pages": total_pages,
            "vulnerabilities": vulnerabilities
        }
        # Create the response
        response = make_response(jsonify(data))
        response.headers["Content-Type"] = "application/json"
        return response

# Resource for fetching recent vulnerabilities
class RecentKevVulnerabilitiesResource(Resource):
    # Cache the response for 5 seconds to reduce server load
    @cache.cached(timeout=5)
    def get(self):
        # Get the 'days' parameter from the query string
        days = request.args.get("days", type=int)
        
        # Validate the 'days' parameter
        if days is None or days < 0:
            return {"message": "Invalid value for days"}, 400
        # Calculate the cutoff date based on the 'days' parameter
        cutoff_date = datetime.utcnow() - timedelta(days=days)
        # Initialize an empty list to store the recent vulnerabilities
        recent_vulnerabilities = []
        # Fetch all vulnerabilities from the collection
        cursor = collection.find()
        # Iterate over the vulnerabilities
        for vulnerability in cursor:
            # Get the date when the vulnerability was added
            date_added_str = vulnerability.get("dateAdded")
            try:
                # Convert the date from string to datetime
                date_added = datetime.strptime(date_added_str, "%Y-%m-%d")
                
                # Check if the vulnerability was added within the cutoff date
                if date_added >= cutoff_date:
                    # If so, serialize the vulnerability and add it to the list
                    recent_vulnerabilities.append(
                        serialize_vulnerability(vulnerability)
                    )
            except ValueError as e:
                # Ignore vulnerabilities with invalid date formats
                pass  
        # Convert the list of recent vulnerabilities to JSON
        response = make_response(jsonify(recent_vulnerabilities))
        # Set the Content-Type of the response to application/json
        response.headers["Content-Type"] = "application/json"
        # Return the response
        return response

class RecentVulnerabilitiesByDaysResource(Resource):
    def get(self, query_type):
        # Get the query parameters
        days = request.args.get("days")
        page = request.args.get("page", default=1)  # Default to page 1 if not provided
        per_page = request.args.get("per_page", default=25)  # Default to 25 if not provided
        # Check if 'days' parameter is provided
        if days is None:
            return {"message": "You must provide 'days' parameter"}, 400
        # Sanitize the 'days' parameter
        sanitized_days = sanitize_query(days)
        # Check if 'days' parameter is a valid integer
        if not isinstance(sanitized_days, int):
            if not sanitized_days.isdigit():
                return {"message": "Invalid value for days parameter"}, 400
            # Limit the 'days' parameter to a maximum of 14
            max_days = 14
            if int(sanitized_days) > max_days:
                return {"message": f"Exceeded the maximum limit of {max_days} days"}, 400
        # Sanitize the 'page' parameter
        sanitized_page = sanitize_query(page)
        # Sanitize and limit the 'per_page' parameter
        per_page = request.args.get("per_page", default=10)  # Default to 10 if not provided
        sanitized_per_page = sanitize_query(str(per_page))  # Convert to string before sanitizing
        sanitized_per_page = min(int(sanitized_per_page), 100)  # Limit to maximum 100
        # Calculate the cutoff date based on the 'days' parameter
        cutoff_date = (datetime.utcnow() - timedelta(days=int(sanitized_days))).strftime("%Y-%m-%d")
        field = "pubDateKev" if query_type == "published" else "pubModDateKev"
        # Calculate the start index for pagination
        start_index = (int(sanitized_page) - 1) * sanitized_per_page
        # Define the fields to return in the response
        projection = {
            "_id": 1,
            "pubDateKev": 1,
            "pubModDateKev": 1,
            "namespaces": 1
        }
        # Query the database for recent vulnerabilities
        recent_vulnerabilities = all_vulns_collection.find(
            {field: {"$gt": cutoff_date}},
            projection
        ).skip(start_index).limit(sanitized_per_page)
        # Process the query results
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
        # Calculate the total number of entries and pages
        total_entries = all_vulns_collection.count_documents({field: {"$gt": cutoff_date}})
        total_pages = math.ceil(total_entries / sanitized_per_page)
        # Prepare the pagination info
        pagination_info = {
            "currentPage": int(sanitized_page),
            "totalPages": total_pages,
            "totalEntries": total_entries,
            "resultsPerPage": sanitized_per_page
        }
        # Prepare the response data
        response_data = {
            "pagination": pagination_info,
            "vulnerabilities": recent_vulnerabilities_list
        }
        # Create the response with the correct content type
        response = make_response(jsonify(response_data))
        response.headers["Content-Type"] = "application/json"
        return response