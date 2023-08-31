from bson import ObjectId
from datetime import datetime


def serialize_all_vulnerability(vulnerability):
    # Handle KeyError exceptions with default values
    gsd = vulnerability.get("GSD", {})
    description = gsd.get("description", "")
    references = gsd.get("references", [])
    namespaces = vulnerability.get("namespaces", {})
    cisa_data = namespaces.get("cisa.gov", {})
    cve_org = namespaces.get("cve.org", {})
    nvd_data = namespaces.get("nvd.nist.gov", {})

    serialized_data = {
        'cveID': str(vulnerability["_id"]),
        'description': description,
        'references': references,
        'cisaData': cisa_data,
        'cve.Org': cve_org,
        'nvdData': nvd_data
    }

    return serialized_data

def nvd_seralizer(vulnerability):
    # Handle KeyError exceptions with default values
    gsd = vulnerability.get("gsd", {})
    namespaces = vulnerability.get("namespaces", {})
    nvd_data = namespaces.get("nvd.nist.gov", {})

    serialized_data = {
        'cveID': str(vulnerability["_id"]),
        'nvdData': nvd_data
    }

    return serialized_data

def mitre_seralizer(vulnerability):
    # Handle KeyError exceptions with default values
    gsd = vulnerability.get("gsd", {})
    namespaces = vulnerability.get("namespaces", {})
    mitre_date = namespaces.get("cve.org", {})

    serialized_data = {
        'cveID': str(vulnerability["_id"]),
        'mitreData': mitre_date
    }

    return serialized_data

def serialize_vulnerability(vulnerability):
    # Define the date format for serialization
    date_format = "%Y-%m-%d"
    
    # Serialize dateAdded field
    date_added = vulnerability.get("dateAdded")
    if isinstance(date_added, datetime):
        date_added_str = date_added.strftime(date_format)
    else:
        date_added_str = date_added
    
    # Serialize dueDate field
    due_date = vulnerability.get("dueDate")
    if isinstance(due_date, datetime):
        due_date_str = due_date.strftime(date_format)
    else:
        due_date_str = due_date
    
    # Handle KeyError exceptions with default values
    notes = vulnerability.get("notes", "")
    product = vulnerability.get("product", "")
    required_action = vulnerability.get("requiredAction", "")
    short_description = vulnerability.get("shortDescription", "")
    vendor_project = vulnerability.get("vendorProject", "")
    vulnerability_name = vulnerability.get("vulnerabilityName", "")
    nvd_data = vulnerability.get("nvdData", [])
    github_pocs = vulnerability.get("githubPocs", [])
    threat_data = vulnerability.get("openThreatData", [])
    
    # Construct the serialized vulnerability dictionary
    serialized_vulnerability = {
        '_id': str(vulnerability["_id"]),
        'cveID': vulnerability["cveID"],
        'dateAdded': date_added_str,
        'dueDate': due_date_str,
        'notes': notes,
        'product': product,
        'requiredAction': required_action,
        'shortDescription': short_description,
        'vendorProject': vendor_project,
        'vulnerabilityName': vulnerability_name,
        'nvdData': nvd_data,
        'githubPocs': github_pocs,
        'openThreatData': threat_data
    }
    
    return serialized_vulnerability
