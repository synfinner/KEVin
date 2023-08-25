from bson import ObjectId
from datetime import datetime

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
    threat_data = vulnerability.get("threatData", [])
    
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
        'threatData': threat_data
    }
    
    return serialized_vulnerability
