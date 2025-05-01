# schema/api.py

from utils.database import all_vulns_collection, collection
from utils.cache_manager import cache_manager, kev_cache as cache
from utils.sanitizer import sanitize_query
from functools import partial
from flask_restful import Resource
from flask import request, Response, json, jsonify, make_response
from pymongo import ASCENDING, DESCENDING
from datetime import datetime, timedelta
import math
import os
from schema.serializers import serialize_vulnerability, serialize_all_vulnerability, nvd_serializer, mitre_serializer, serialize_githubpocs
from gevent import spawn, joinall
from gevent.pool import Pool

# Load env using python-dotenv
from dotenv import load_dotenv
load_dotenv()

# Configure the maximum number of concurrent greenlets
# This helps prevent server overload from too many concurrent operations
# Ensure we have at least 1 greenlet to prevent crashes
MAX_GREENLETS = max(1, int(os.environ.get('MAX_GREENLETS', 100)))
# Create a global pool to limit concurrent greenlets
GREENLET_POOL = Pool(MAX_GREENLETS)

class BaseResource(Resource):
    def handle_error(self, message, status=404):
        response = {"message": message}
        return make_response(jsonify(response), status)

    def make_json_response(self, data, status=200):
        return make_response(jsonify(data), status)

# Resource for fectching mitre and nvd data from the cveland via CVE-ID,
# which is the _id field in the cveland collection
class cveLandResource(BaseResource):
    def get(self, cve_id):
        """
        Retrieve vulnerability data by CVE ID.

        This method checks the cache for existing data associated with the
        provided CVE ID. If cached data is found, it returns that data.
        If not, it sanitizes the CVE ID, queries the database for the
        corresponding vulnerability, and caches the result for future requests.

        Parameters:
        cve_id (str): The CVE ID to look up.

        Returns:
        Response: A JSON response containing the vulnerability data or an
                  error message if the input parameters are invalid or the
                  vulnerability is not found.
        """
        # Sanitize the CVE ID first. Fix #179
        sanitized_cve_id = sanitize_query(cve_id)
        if sanitized_cve_id is None:
            return self.handle_error("Invalid CVE ID", 400)

        # Use partial to create a new function that includes the cve_id in the key prefix
        cache_key_func = partial(self.make_cache_key, cve_id=sanitized_cve_id)

        # Spawn greenlets for concurrent execution using the pool
        greenlets = []
        greenlets.append(GREENLET_POOL.spawn(self.get_cached_data, cache_key_func))
        greenlets.append(GREENLET_POOL.spawn(self.query_vulnerability, sanitized_cve_id))

        # Wait for all greenlets to complete
        joinall(greenlets)

        cached_data = greenlets[0].value
        vulnerability = greenlets[1].value

        if cached_data:
            return self.make_json_response(cached_data)
        if not vulnerability:
            return self.handle_error("Vulnerability not found")

        data = serialize_all_vulnerability(vulnerability)
        cache_manager.set(cache_key_func(), data,timeout=180)  # Manually caching the data
        return self.make_json_response(data)

    def get_cached_data(self, cache_key_func):
        """Fetch cached data."""
        return cache_manager.get(cache_key_func())

    def query_vulnerability(self, sanitized_cve_id):
        """Query the database for the vulnerability."""
        return all_vulns_collection.find_one({"_id": sanitized_cve_id})

    def make_cache_key(self, cve_id):
        """ Generate a unique cache key including the CVE ID. """
        return f"cve_data_{cve_id}"

# Resource for NVD data from the cveland via CVE-ID, which is the _id field in the cveland collection
class cveNVDResource(BaseResource):
    @cache()
    def get(self, cve_id):
        """
        Retrieve NVD data for a specific CVE ID.

        This method fetches vulnerability information from the 'all_vulns_collection'
        based on the provided CVE ID. It sanitizes the input to prevent injection
        attacks and returns the serialized NVD data. If the vulnerability is not
        found, it returns a 404 error.

        Parameters:
        cve_id (str): The CVE ID of the vulnerability to retrieve.

        Returns:
        Response: A JSON response containing the serialized NVD data or an
                  error message if the vulnerability is not found.
        """
        # Sanitize the input CVE ID
        sanitized_cve_id = sanitize_query(cve_id)
        vulnerability = all_vulns_collection.find_one({"_id": sanitized_cve_id})
        if not vulnerability:
            return self.handle_error("Vulnerability not found")

        data = nvd_serializer(vulnerability)
        return self.make_json_response(data)

        
# This class defines a resource for fetching Mitre data for a specific CVE-ID from the 'cveland' collection
class cveMitreResource(BaseResource):
    @cache()  # Use caching to improve performance
    def get(self, cve_id):
        """
        Retrieve Mitre data for a specific CVE ID.

        This method fetches vulnerability information from the 'all_vulns_collection'
        based on the provided CVE ID. It sanitizes the input to prevent injection
        attacks and returns the serialized Mitre data. If the vulnerability is not
        found, it returns a 404 error.

        Parameters:
        cve_id (str): The CVE ID of the vulnerability to retrieve.

        Returns:
        Response: A JSON response containing the serialized Mitre data or an
                  error message if the vulnerability is not found.
        """
        # Sanitize the input CVE ID to prevent injection attacks
        sanitized_cve_id = sanitize_query(cve_id)
        # Fetch the vulnerability with the sanitized CVE ID from the 'all_vulns_collection'
        vulnerability = all_vulns_collection.find_one({"_id": sanitized_cve_id})
        if not vulnerability:
            # If the vulnerability is not found, return a 404 error with a message
            return self.handle_error("Vulnerability not found")
        # If the vulnerability is found, serialize it using the 'mitre_serializer' function
        data = mitre_serializer(vulnerability)
        # Return the JSON response with the serialized data
        return self.make_json_response(data)
    
# Resource for fetching a specific vulnerability by CVE ID
class VulnerabilityResource(BaseResource):
    def get(self, cve_id):
        """
        Retrieve vulnerability details by CVE ID.

        This method fetches vulnerability information based on the provided
        CVE ID. It supports optional retrieval of references, specifically
        for Proof of Concepts (PoCs). The method sanitizes the input
        parameters and checks the cache for existing data before querying
        the database.

        Parameters:
        cve_id (str): The CVE ID of the vulnerability to retrieve.

        Query Parameters:
        - references (str): Optional parameter to specify if PoCs should be
                            returned. If set to 'pocs', the method retrieves
                            PoCs instead of the standard vulnerability data.

        Returns:
        Response: A JSON response containing the vulnerability data or an
                  error message if the input parameters are invalid or the
                  vulnerability is not found.
        """
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
            # Spawn greenlets for cache check and database query using the pool
            greenlets = []
            greenlets.append(GREENLET_POOL.spawn(self.get_cached_data, sanitized_cve_id))
            greenlets.append(GREENLET_POOL.spawn(self.query_vulnerability, sanitized_cve_id))

            # Wait for all greenlets to complete
            joinall(greenlets)

            cached_data = greenlets[0].value
            vulnerability = greenlets[1].value

            if cached_data:
                data = serialize_vulnerability(cached_data)
            elif not vulnerability:
                return self.handle_error("Vulnerability not found")
            else:
                cache_manager.set(sanitized_cve_id, vulnerability)
                data = serialize_vulnerability(vulnerability)

        return self.make_json_response(data)

    def get_cached_data(self, sanitized_cve_id):
        """Fetch cached data."""
        return cache_manager.get(sanitized_cve_id)

    def query_vulnerability(self, sanitized_cve_id):
        """Query the database for the vulnerability."""
        return collection.find_one({"cveID": sanitized_cve_id})

# This class defines a resource for fetching all KEV vulnerabilities
class AllKevVulnerabilitiesResource(BaseResource):
    @cache(timeout=120, key_prefix="all_kev_vulns", query_string=True)
    def get(self):
        """
        Retrieve all KEV vulnerabilities with optional filtering, sorting, and pagination.

        This method fetches vulnerabilities from the database, allowing for
        pagination, sorting, and filtering based on user-defined parameters.
        It returns a structured response containing the vulnerabilities and
        pagination information.

        Query Parameters:
        - page (int): The page number for pagination (default is 1).
        - per_page (int): The number of results per page (default is 25, max is 100).
        - sort (str): The field to sort by (default is "dateAdded").
        - order (str): The sort order, either "asc" or "desc" (default is "desc").
        - search (str): A search term to filter vulnerabilities.
        - filter (str): A filter to include only vulnerabilities related to ransomware.
        - actor (str): A search term to filter vulnerabilities by potential threat actors.

        Returns:
        Response: A JSON response containing pagination info and a list of
                  vulnerabilities, or an error message if an internal error occurs.
        """
        try:
            try:
                page = int(request.args.get("page", 1))
                per_page = max(1, min(100, int(request.args.get("per_page", 25))))
            except ValueError:
                return self.handle_error("Invalid page or per_page parameter. Must be integers.", 400)

            sort_param = sanitize_query(request.args.get("sort", "dateAdded"))
            order_param = sanitize_query(request.args.get("order", "desc"))
            search_query = sanitize_query(request.args.get("search", ''))
            filter_ransomware = sanitize_query(request.args.get("filter", ''))
            actor_query = sanitize_query(request.args.get("actor", ''))

            query = {}
            if search_query:
                search_term = search_query.strip()
                # Only search in the vendorProject field
                query["vendorProject"] = {"$regex": search_term, "$options": "i"}
            if filter_ransomware.lower() == 'ransomware':
                query["knownRansomwareCampaignUse"] = "Known"
            if actor_query and actor_query.strip():  # Ensure actor_query is not empty or just whitespace
                # Fuzzy match for actor search
                actor_query = {"$or": [
                    {"openThreatData.communityAdversaries": {"$regex": actor_query.strip(), "$options": "i"}},
                    {"openThreatData.adversaries": {"$regex": actor_query.strip(), "$options": "i"}}
                ]}
                query.update(actor_query)  # Merge actor query into the main query

            sort_order = DESCENDING if order_param == "desc" else ASCENDING
            sort_criteria = [(sort_param, sort_order)]

            # Always run the query - caching is now handled at the method level
            total_vulns = self.count_documents(query)
            vulnerabilities = self.fetch_vulnerabilities(query, sort_criteria, page, per_page)

            total_pages = math.ceil(total_vulns / per_page)

            return self.make_json_response({
                "page": page,
                "per_page": per_page,
                "total_vulns": total_vulns,
                "total_pages": total_pages,
                "vulnerabilities": [serialize_vulnerability(v) for v in vulnerabilities]
            })
        except Exception as e:
            return self.handle_error("An internal server error occurred! ", 500)

    def count_documents(self, query):
        """Count the total number of vulnerabilities matching the query."""
        try:
            return collection.count_documents(query)
        except Exception as e:
            raise e

    def fetch_vulnerabilities(self, query, sort_criteria, page, per_page):
        """Fetch vulnerabilities from the database."""
        try:
            cursor = collection.find(query).sort(sort_criteria).skip((page - 1) * per_page).limit(per_page)
            return list(cursor)  # Return cursor as a list
        except Exception as e:
            raise e

# Resource for fetching recent vulnerabilities
class RecentKevVulnerabilitiesResource(BaseResource):
    @cache(timeout=60, key_prefix='recent_kevs_', query_string=True)
    def get(self):
        """
        Retrieve recent KEV vulnerabilities added within a specified number of days.

        This method fetches vulnerabilities from the database that were added
        within the specified number of days. It validates the 'days' parameter
        and returns a list of serialized vulnerabilities that meet the criteria.

        Query Parameters:
        - days (int): The number of days to look back for recent vulnerabilities.

        Returns:
        Response: A JSON response containing a list of recent vulnerabilities
                  or an error message if the input parameter is invalid.
        """
        # Get the 'days' parameter from the query string
        days = request.args.get("days", type=int)
        # Validate the 'days' parameter
        if days is None or days < 0:
            return self.handle_error("Invalid value for days", 400)
        # Limit days to a maximum of 100
        if days > 100:
            return self.handle_error("Exceeded the maximum limit of 100 days", 400)
        # Calculate the cutoff date based on the 'days' parameter
        cutoff_date = datetime.utcnow() - timedelta(days=days)
        cutoff_date_str = cutoff_date.strftime("%Y-%m-%d")
        
        # Use server-side filtering - only fetch vulnerabilities with dateAdded >= cutoff_date
        cursor = collection.find({"dateAdded": {"$gte": cutoff_date_str}})
        
        # Process results in batches to avoid memory issues
        # Ensure batch_size is at least 1 to prevent crashes
        batch_size = max(1, MAX_GREENLETS)
        all_results = []
        
        # Process the cursor in batches
        batch = []
        for vulnerability in cursor:
            batch.append(vulnerability)
            
            # Process batch when it reaches the maximum size
            if len(batch) >= batch_size:
                greenlets = []
                
                # Process each vulnerability in the batch
                for vuln in batch:
                    greenlets.append(GREENLET_POOL.spawn(serialize_vulnerability, vuln))
                
                # Wait for all greenlets to complete
                joinall(greenlets)
                
                # Collect results and extend the list
                batch_results = [g.value for g in greenlets if g.value]
                all_results.extend(batch_results)
                
                # Clear batch for next iteration
                batch = []
        
        # Process any remaining items in the final batch
        if batch:
            greenlets = []
            for vuln in batch:
                greenlets.append(GREENLET_POOL.spawn(serialize_vulnerability, vuln))
            
            joinall(greenlets)
            batch_results = [g.value for g in greenlets if g.value]
            all_results.extend(batch_results)
        
        # Use all collected results
        recent_vulnerabilities = all_results

        # Return the JSON response with the serialized data
        return self.make_json_response(recent_vulnerabilities)

    def process_vulnerability(self, vulnerability, cutoff_date):
        """Process a single vulnerability to check if it meets the cutoff date."""
        date_added_str = vulnerability.get("dateAdded")
        try:
            # Convert the date from string to datetime
            date_added = datetime.strptime(date_added_str, "%Y-%m-%d")
            # Check if the vulnerability was added within the cutoff date
            if date_added >= cutoff_date:
                return serialize_vulnerability(vulnerability)
        except ValueError:
            # Ignore vulnerabilities with invalid date formats
            return None

class RecentVulnerabilitiesByDaysResource(BaseResource):
    def __init__(self, query_type=None):
        self.query_type = query_type  # Store the query_type for use in the get method

    @cache(timeout=600, key_prefix="recent_days_vulnerabilities", query_string=True) # Cache for 10 minutes
    def get(self):
        """
        Retrieve recent vulnerabilities based on the specified number of days.

        This method fetches vulnerabilities that were published or modified
        within a specified number of days. It supports pagination and
        returns a structured response containing the vulnerabilities and
        pagination information.

        Query Parameters:
        - days (int): The number of days to look back for recent vulnerabilities.
        - page (int): The page number for pagination (default is 1).
        - per_page (int): The number of results per page (default is 25).

        Returns:
        Response: A JSON response containing the list of recent vulnerabilities
                  and pagination information, or an error message if the input
                  parameters are invalid.
        """
        # Get the query parameters
        days = request.args.get("days")
        page = request.args.get("page", default=1, type=int)  # Default to page 1 if not provided
        per_page = request.args.get("per_page", default=25, type=int)
        if per_page > 100:
            return self.handle_error("The 'per_page' parameter cannot exceed 100.", 400)
        per_page = max(1, per_page)  # Ensure per_page is at least 1
        # Check if 'days' parameter is provided
        if days is None:
            return self.handle_error("You must provide 'days' parameter", 400)
        # Sanitize the 'days' parameter
        days = sanitize_query(days)
        if not days.isdigit() or int(days) < 0:
            return self.handle_error("Invalid value for days parameter. Please provide a non-negative integer no greater than 14.", 400)
        if int(days) > 14:  # Limit the 'days' parameter to a maximum of 14
            return self.handle_error("Exceeded the maximum limit of 14 days", 400)

        # Process the request directly - caching is handled at the method level now
        cutoff_date = (datetime.utcnow() - timedelta(days=int(days))).strftime("%Y-%m-%d")
        field = (
            "namespaces.nvd_nist_gov.cve.published" 
            if self.query_type == "published" 
            else "namespaces.nvd_nist_gov.cve.lastModified"
        )

        # Create a list of greenlets for concurrent execution using the pool
        greenlets = []

        # Spawn a greenlet for counting total entries
        greenlets.append(GREENLET_POOL.spawn(self.count_total_entries, field, cutoff_date))
        # Spawn a greenlet for querying the database with the correct parameters
        greenlets.append(GREENLET_POOL.spawn(self.query_database, field, cutoff_date, page, per_page, sort_order=-1))  # -1 for descending order

        # Wait for all greenlets to complete
        joinall(greenlets)

        # Get the total entries and recent vulnerabilities list
        total_entries = greenlets[0].value
        recent_vulnerabilities_list = greenlets[1].value

        # Check if recent_vulnerabilities_list is None
        if recent_vulnerabilities_list is None:
            return self.handle_error("No vulnerabilities found", 404)

        # Calculate total pages
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
            "vulnerabilities": self.add_id_first(recent_vulnerabilities_list)  # Ensure _id is first
        }
        return self.make_json_response(response_data)
 
    def count_total_entries(self, field, cutoff_date):
        """Count the total number of vulnerabilities matching the query."""
        return all_vulns_collection.count_documents({field: {"$gt": cutoff_date}})

    def query_database(self, field, cutoff_date, page, per_page, sort_order=1):
        """Query the database for recent vulnerabilities with pagination."""
        skip = (page - 1) * per_page  # Calculate how many documents to skip
        recent_vulnerabilities = all_vulns_collection.find(
            {field: {"$gt": cutoff_date}}
        ).sort(field, sort_order).skip(skip).limit(per_page)  # Apply sorting and pagination
        return [v for v in recent_vulnerabilities]  # Convert cursor to list

    def add_id_first(self, vulnerabilities):
        """Ensure the _id is the first displayed value in each vulnerability."""
        for vulnerability in vulnerabilities:
            if '_id' in vulnerability:
                vulnerability['_id'] = vulnerability.pop('_id')  # Move _id to the front
        return vulnerabilities

    