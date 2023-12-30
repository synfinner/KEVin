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
from schema.serializers import serialize_vulnerability, serialize_all_vulnerability, nvd_seralizer, mitre_seralizer

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
        
# Resource for Mitre data from the cveland via CVE-ID, which is the _id field in the cveland collection
class cveMitreResource(Resource):
    @cache.cached()
    def get(self, cve_id):
        # Sanitize the input CVE ID
        sanitized_cve_id = sanitize_query(cve_id)
        vulnerability = all_vulns_collection.find_one({"_id": sanitized_cve_id})
        if vulnerability:
            data = mitre_seralizer(vulnerability)
            #return mitre_seralizer(vulnerability)
        else:
            return {"message": "Vulnerability not found"}, 404
        response = Response(json.dumps(data), content_type="application/json")
        return response

# Resource for fetching a specific vulnerability by CVE ID
class VulnerabilityResource(Resource):
    @cache.cached()
    def get(self, cve_id):
        # Sanitize the input CVE ID
        sanitized_cve_id = sanitize_query(cve_id)
        
        vulnerability = collection.find_one({"cveID": sanitized_cve_id})
        if vulnerability:
            data = serialize_vulnerability(vulnerability)
            #return serialize_vulnerability(vulnerability)
        else:
            return {"message": "Vulnerability not found"}, 404
        response = Response(json.dumps(data), content_type="application/json")
        return response

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

        """
        return {
            "page": page,
            "per_page": per_page,
            "total_vulns": total_vulns,
            "total_pages": total_pages,
            "vulnerabilities": vulnerabilities
        }
        """
        data = {
            "page": page,
            "per_page": per_page,
            "total_vulns": total_vulns,
            "total_pages": total_pages,
            "vulnerabilities": vulnerabilities
        }
        response = make_response(jsonify(data))
        response.headers["Content-Type"] = "application/json"
        return response


# Resource for fetching recent vulnerabilities
class RecentKevVulnerabilitiesResource(Resource):
    @cache.cached(timeout=5)
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
        response = make_response(jsonify(recent_vulnerabilities))
        response.headers["Content-Type"] = "application/json"
        return response
        #return recent_vulnerabilities

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

        #return response_data
        response = make_response(jsonify(response_data))
        response.headers["Content-Type"] = "application/json"
        return response