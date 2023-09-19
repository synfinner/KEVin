from bson import ObjectId
from datetime import datetime

def serialize_date(date_value, format="%Y-%m-%d"):
    if isinstance(date_value, datetime):
        return date_value.strftime(format)
    return date_value

def extract_keys(data, keys):
    """Utility function to extract certain keys from a dictionary."""
    return {key: data.get(key, {}) for key in keys}

def serialize_all_vulnerability(vulnerability):
    data = extract_keys(vulnerability, ['GSD', 'namespaces'])
    return {
        'cveID': str(vulnerability["_id"]),
        'description': data['GSD'].get('description', ''),
        'references': data['GSD'].get('references', []),
        'cisaData': data['namespaces'].get('cisa.gov', {}),
        'cve.Org': data['namespaces'].get('cve.org', {}),
        'nvdData': data['namespaces'].get('nvd.nist.gov', {})
    }

def nvd_seralizer(vulnerability):
    nvd_data = extract_keys(vulnerability.get("namespaces", {}), ["nvd.nist.gov"])
    return {
        'cveID': str(vulnerability["_id"]),
        'nvdData': nvd_data["nvd.nist.gov"]
    }

def mitre_seralizer(vulnerability):
    mitre_data = extract_keys(vulnerability.get("namespaces", {}), ["cve.org"])
    return {
        'cveID': str(vulnerability["_id"]),
        'mitreData': mitre_data["cve.org"]
    }

def serialize_vulnerability(vulnerability):
    # First, serialize the fields that you want at the top
    serialized_data = {
        '_id': str(vulnerability["_id"]),
        'cveID': vulnerability["cveID"],
        'dateAdded': serialize_date(vulnerability.get("dateAdded")),
        'dueDate': serialize_date(vulnerability.get("dueDate"))
    }
    
    # Extract other fields and update the dictionary
    fields_to_extract = [
        'notes', 'product', 'requiredAction', 'shortDescription', 
        'vendorProject', 'vulnerabilityName', 'nvdData', 
        'githubPocs', 'openThreatData'
    ]
    serialized_data.update(extract_keys(vulnerability, fields_to_extract))
    
    return serialized_data

def serialize_recent_cve_vulnerability(vulnerability):
    return {
        "_id": vulnerability["_id"],
        "pubDateKev": vulnerability["pubDateKev"].isoformat(),
        "pubModDateKev": vulnerability["pubModDateKev"].isoformat(),
        "nvdData": vulnerability.get("nvdData", None)
    }
