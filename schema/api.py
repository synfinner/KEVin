# schema/api.py

from datetime import datetime, timedelta, timezone
from functools import partial
import math
import os
import re

from dotenv import load_dotenv
from flask import jsonify, make_response, request
from flask_restful import Resource
from pymongo import ASCENDING, DESCENDING
from pymongo.errors import PyMongoError

from schema.serializers import (
    mitre_serializer,
    nvd_serializer,
    serialize_all_vulnerability,
    serialize_githubpocs,
    serialize_vulnerability,
)
from utils.backend_capacity import (
    BackendBusyError,
    BackendTimeoutError,
    run_backend_tasks,
)
from utils.cache_manager import (
    CacheBackendUnavailable,
    cache_manager,
    kev_cache as cache,
)
from utils.database import all_vulns_collection, collection
from utils.sanitizer import sanitize_query

# Load env using python-dotenv
load_dotenv()

# Fields clients are allowed to sort on for KEV listings. Keep in sync with
# Mongo indexes so we never trigger an expensive collection scan.
ALLOWED_KEV_SORT_FIELDS = {"dateAdded", "dueDate", "cveID"}
MAX_PAGE = max(1, int(os.environ.get("MAX_PAGE", "1000")))
RECENT_KEV_MAX_RESULTS = max(
    1,
    int(os.environ.get("RECENT_KEV_MAX_RESULTS", "500")),
)
MONGO_QUERY_MAX_TIME_MS = max(
    100,
    int(os.environ.get("MONGO_QUERY_MAX_TIME_MS", "5000")),
)
RECENT_VULNERABILITY_QUERY_PARAMETERS = {"days", "page", "per_page"}
RECENT_KEV_QUERY_PARAMETERS = {"days", "limit"}
ALL_KEV_QUERY_PARAMETERS = {
    "actor",
    "filter",
    "order",
    "page",
    "per_page",
    "search",
    "sort",
}

# Timeout in seconds for admitted backend work to finish.
GREENLET_TIMEOUT = max(1, int(os.environ.get('GREENLET_TIMEOUT', "10")))

def validate_page(page):
    """Reject non-positive and unbounded pages before MongoDB skip() calls."""
    if page < 1:
        return None
    return min(page, MAX_PAGE)


def _strict_query_integer(name, default=None):
    """Return one ASCII-decimal query value or raise a client-safe error."""
    values = request.args.getlist(name)
    if not values:
        if default is not None:
            return default
        raise ValueError(f"You must provide '{name}' parameter")
    if len(values) != 1:
        raise ValueError(f"Duplicate '{name}' query parameters are not allowed")

    value = values[0]
    if not re.fullmatch(r"[0-9]+", value):
        raise ValueError(f"Invalid {name} parameter. Must be an integer.")
    return int(value)


def parse_recent_vulnerability_query():
    """Validate and canonicalize recent published/modified query parameters."""
    unknown_parameters = sorted(
        set(request.args.keys()) - RECENT_VULNERABILITY_QUERY_PARAMETERS
    )
    if unknown_parameters:
        names = ", ".join(unknown_parameters)
        raise ValueError(f"Unsupported query parameter(s): {names}")

    days = _strict_query_integer("days")
    page = _strict_query_integer("page", default=1)
    page = validate_page(page)
    per_page = _strict_query_integer("per_page", default=25)

    if days > 30:
        raise ValueError("Exceeded the maximum limit of 30 days")
    if page is None:
        raise ValueError("Invalid page parameter. Must be a positive integer.")
    if per_page > 100:
        raise ValueError("The 'per_page' parameter cannot exceed 100.")

    return days, page, max(1, per_page)


def canonical_recent_vulnerability_query_items():
    """Return stable cache-key items for one validated recent query."""
    days, page, per_page = parse_recent_vulnerability_query()
    return [
        ("days", [str(days)]),
        ("page", [str(page)]),
        ("per_page", [str(per_page)]),
    ]


def parse_recent_kev_query():
    """Validate and canonicalize the bounded recent-KEV query parameters."""
    unknown_parameters = sorted(
        set(request.args.keys()) - RECENT_KEV_QUERY_PARAMETERS
    )
    if unknown_parameters:
        names = ", ".join(unknown_parameters)
        raise ValueError(f"Unsupported query parameter(s): {names}")

    days = _strict_query_integer("days")
    result_limit = _strict_query_integer(
        "limit",
        default=RECENT_KEV_MAX_RESULTS,
    )

    if days > 100:
        raise ValueError("Exceeded the maximum limit of 100 days")
    if result_limit < 1 or result_limit > RECENT_KEV_MAX_RESULTS:
        raise ValueError(
            f"Limit must be between 1 and {RECENT_KEV_MAX_RESULTS} results"
        )

    return days, result_limit


def canonical_recent_kev_query_items():
    """Return stable cache-key items for one validated recent-KEV query."""
    days, result_limit = parse_recent_kev_query()
    return [
        ("days", [str(days)]),
        ("limit", [str(result_limit)]),
    ]


def parse_all_kev_query():
    """Validate and canonicalize pagination, filtering, and sort parameters."""
    supplied_parameters = set(request.args.keys())
    unknown_parameters = sorted(supplied_parameters - ALL_KEV_QUERY_PARAMETERS)
    if unknown_parameters:
        names = ", ".join(unknown_parameters)
        raise ValueError(f"Unsupported query parameter(s): {names}")

    duplicate_parameters = sorted(
        name for name in supplied_parameters if len(request.args.getlist(name)) != 1
    )
    if duplicate_parameters:
        names = ", ".join(duplicate_parameters)
        raise ValueError(f"Duplicate query parameter(s) are not allowed: {names}")

    try:
        page = int(request.args.get("page", 1))
        per_page = int(request.args.get("per_page", 25))
    except ValueError as exc:
        raise ValueError(
            "Invalid page or per_page parameter. Must be integers."
        ) from exc

    page = validate_page(page)
    if page is None:
        raise ValueError("Invalid page parameter. Must be a positive integer.")
    per_page = max(1, min(100, per_page))

    sort_param = (
        sanitize_query(request.args.get("sort", "dateAdded")) or ""
    ).strip()
    if sort_param not in ALLOWED_KEV_SORT_FIELDS:
        raise ValueError("Unsupported sort parameter")

    order_param = (
        sanitize_query(request.args.get("order", "desc")) or "desc"
    ).lower()
    if order_param not in {"asc", "desc"}:
        order_param = "desc"

    search_query = (
        sanitize_query(request.args.get("search", "")) or ""
    ).strip().lower()
    filter_ransomware = sanitize_query(request.args.get("filter", "")) or ""
    if filter_ransomware:
        filter_ransomware = filter_ransomware.lower()
        if filter_ransomware != "ransomware":
            raise ValueError("Invalid filter parameter. Must be 'ransomware'.")
    actor_query = (
        sanitize_query(request.args.get("actor", "")) or ""
    ).strip().lower()

    return (
        page,
        per_page,
        sort_param,
        order_param,
        search_query,
        filter_ransomware,
        actor_query,
    )


def canonical_all_kev_query_items():
    """Return stable cache-key items for one validated KEV list query."""
    query_values = parse_all_kev_query()
    parameter_names = (
        "page",
        "per_page",
        "sort",
        "order",
        "search",
        "filter",
        "actor",
    )
    return [
        (name, [str(value)])
        for name, value in zip(parameter_names, query_values, strict=True)
    ]

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

        try:
            cached_data = self.get_cached_data(cache_key_func)
        except CacheBackendUnavailable:
            return self.handle_error("Cache temporarily unavailable", 503)
        if cached_data is not None:
            return self.make_json_response(cached_data)

        cache_key = cache_key_func()
        with cache_manager.singleflight(cache_key) as acquired:
            if not acquired:
                return self.handle_error("Backend busy", 503)

            try:
                cached_data = cache_manager.get(cache_key)
            except CacheBackendUnavailable:
                return self.handle_error("Cache temporarily unavailable", 503)
            if cached_data is not None:
                return self.make_json_response(cached_data)

            try:
                vulnerability = run_backend_tasks(
                    [partial(self.query_vulnerability, sanitized_cve_id)],
                    timeout=GREENLET_TIMEOUT,
                )[0]
            except BackendBusyError:
                return self.handle_error("Backend busy", 503)
            except BackendTimeoutError:
                return self.handle_error("Upstream timeout", 504)
            except PyMongoError:
                return self.handle_error("Backend unavailable", 503)

            if vulnerability:
                data = serialize_all_vulnerability(vulnerability)
                cache_manager.set(cache_key, data, timeout=180)
                return self.make_json_response(data)

        return self.handle_error("Vulnerability not found")

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
        if sanitized_cve_id is None:
            return self.handle_error("Invalid CVE ID", 400)
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
        if sanitized_cve_id is None:
            return self.handle_error("Invalid CVE ID", 400)
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
        if sanitized_cve_id is None:
            return self.handle_error("Invalid CVE ID", 400)
        # Get the 'references' argument and sanitize it
        references_raw = request.args.get('references')
        references_arg = sanitize_query(references_raw)
        if references_raw is not None and references_arg is None:
            return self.handle_error("Invalid value for references parameter", 400)
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
            try:
                cached_data = self.get_cached_data(sanitized_cve_id)
            except CacheBackendUnavailable:
                return self.handle_error("Cache temporarily unavailable", 503)
            if cached_data is not None:
                data = serialize_vulnerability(cached_data)
            else:
                with cache_manager.singleflight(sanitized_cve_id) as acquired:
                    if not acquired:
                        return self.handle_error("Backend busy", 503)

                    try:
                        cached_data = cache_manager.get(sanitized_cve_id)
                    except CacheBackendUnavailable:
                        return self.handle_error("Cache temporarily unavailable", 503)
                    if cached_data is not None:
                        data = serialize_vulnerability(cached_data)
                    else:
                        try:
                            vulnerability = run_backend_tasks(
                                [
                                    partial(
                                        self.query_vulnerability,
                                        sanitized_cve_id,
                                    )
                                ],
                                timeout=GREENLET_TIMEOUT,
                            )[0]
                        except BackendBusyError:
                            return self.handle_error("Backend busy", 503)
                        except BackendTimeoutError:
                            return self.handle_error("Upstream timeout", 504)
                        except PyMongoError:
                            return self.handle_error("Backend unavailable", 503)

                        if not vulnerability:
                            return self.handle_error("Vulnerability not found")
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
    @cache(
        timeout=120,
        key_prefix="all_kev_vulns",
        query_string=canonical_all_kev_query_items,
    )
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
            (
                page,
                per_page,
                sort_param,
                order_param,
                search_query,
                filter_ransomware,
                actor_query,
            ) = parse_all_kev_query()

            query = {}
            if search_query:
                # Escape special characters in the search term even if it's already sanitized.
                search_term = re.escape(search_query)
                # Only search in the vendorProject field
                query["vendorProject"] = {"$regex": search_term, "$options": "i"}
            if filter_ransomware:
                query["knownRansomwareCampaignUse"] = "Known"
            if actor_query:
                # Fuzzy match for actor search
                actor_query = {"$or": [
                    {"openThreatData.communityAdversaries": {"$regex": actor_query, "$options": "i"}},
                    {"openThreatData.adversaries": {"$regex": actor_query, "$options": "i"}}
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
        except Exception:
            return self.handle_error("An internal server error occurred! ", 500)

    def count_documents(self, query):
        """Count the total number of vulnerabilities matching the query."""
        try:
            return collection.count_documents(
                query,
                maxTimeMS=MONGO_QUERY_MAX_TIME_MS,
            )
        except Exception as e:
            raise e

    def fetch_vulnerabilities(self, query, sort_criteria, page, per_page):
        """Fetch vulnerabilities from the database."""
        try:
            cursor = (
                collection.find(query)
                .sort(sort_criteria)
                .skip((page - 1) * per_page)
                .limit(per_page)
                .max_time_ms(MONGO_QUERY_MAX_TIME_MS)
            )
            return list(cursor)  # Return cursor as a list
        except Exception as e:
            raise e

# Resource for fetching recent vulnerabilities
class RecentKevVulnerabilitiesResource(BaseResource):
    @cache(
        timeout=60,
        key_prefix="recent_kevs_",
        query_string=canonical_recent_kev_query_items,
    )
    def get(self):
        """
        Retrieve recent KEV vulnerabilities added within a specified number of days.

        This method fetches vulnerabilities from the database that were added
        within the specified number of days. It validates the 'days' parameter
        and returns a list of serialized vulnerabilities that meet the criteria.

        Query Parameters:
        - days (int): The number of days to look back for recent vulnerabilities.
        - limit (int): Maximum records to return, capped by server configuration.

        Returns:
        Response: A JSON response containing a list of recent vulnerabilities
                  or an error message if the input parameter is invalid.
        """
        # Reuse the cache-key parser so accepted behavior and cache identity
        # cannot drift apart.
        days, result_limit = parse_recent_kev_query()
        cutoff_date = datetime.now(timezone.utc) - timedelta(days=days)
        cutoff_date_str = cutoff_date.strftime("%Y-%m-%d")

        try:
            vulnerabilities = run_backend_tasks(
                [
                    partial(
                        self.query_recent_vulnerabilities,
                        cutoff_date_str,
                        result_limit,
                    )
                ],
                timeout=GREENLET_TIMEOUT,
            )[0]
        except BackendBusyError:
            return self.handle_error("Backend busy", 503)
        except BackendTimeoutError:
            return self.handle_error("Upstream timeout", 504)
        except PyMongoError:
            return self.handle_error("Backend unavailable", 503)

        return self.make_json_response(vulnerabilities)

    def query_recent_vulnerabilities(self, cutoff_date, result_limit):
        """Materialize one bounded, deadline-limited query under admission."""
        cursor = (
            collection.find({"dateAdded": {"$gte": cutoff_date}})
            .sort("dateAdded", DESCENDING)
            .limit(result_limit)
            .max_time_ms(MONGO_QUERY_MAX_TIME_MS)
        )
        return [serialize_vulnerability(vulnerability) for vulnerability in cursor]

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

    @cache(
        timeout=600,
        key_prefix="recent_days_vulnerabilities",
        query_string=canonical_recent_vulnerability_query_items,
    )
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
        # Reuse the cache-key parser so accepted behavior cannot drift from
        # cache and singleflight identity.
        days, page, per_page = parse_recent_vulnerability_query()

        # Process the request directly - caching is handled at the method level now
        cutoff_date = (datetime.now(timezone.utc) - timedelta(days=days)).strftime(
            "%Y-%m-%d"
        )
        field = (
            "namespaces.nvd_nist_gov.cve.published" 
            if self.query_type == "published" 
            else "namespaces.nvd_nist_gov.cve.lastModified"
        )

        try:
            total_entries, recent_vulnerabilities_list = run_backend_tasks(
                [
                    partial(self.count_total_entries, field, cutoff_date),
                    partial(
                        self.query_database,
                        field,
                        cutoff_date,
                        page,
                        per_page,
                        sort_order=-1,
                    ),
                ],
                timeout=GREENLET_TIMEOUT,
            )
        except BackendBusyError:
            return self.handle_error("Backend busy", 503)
        except BackendTimeoutError:
            return self.handle_error("Upstream timeout", 504)
        except PyMongoError:
            return self.handle_error("Backend unavailable", 503)

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
        return all_vulns_collection.count_documents(
            {field: {"$gt": cutoff_date}},
            maxTimeMS=MONGO_QUERY_MAX_TIME_MS,
        )

    def query_database(self, field, cutoff_date, page, per_page, sort_order=1):
        """Query the database for recent vulnerabilities with pagination."""
        skip = (page - 1) * per_page  # Calculate how many documents to skip
        recent_vulnerabilities = all_vulns_collection.find(
            {field: {"$gt": cutoff_date}}
        ).sort(field, sort_order).skip(skip).limit(per_page).max_time_ms(
            MONGO_QUERY_MAX_TIME_MS
        )
        return [v for v in recent_vulnerabilities]  # Convert cursor to list

    def add_id_first(self, vulnerabilities):
        """Ensure the _id is the first displayed value in each vulnerability."""
        for vulnerability in vulnerabilities:
            if '_id' in vulnerability:
                vulnerability['_id'] = vulnerability.pop('_id')  # Move _id to the front
        return vulnerabilities

    
