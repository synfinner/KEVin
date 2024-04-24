from bson import ObjectId
from datetime import datetime

def serialize_date(date_value, format="%Y-%m-%d"):
    if isinstance(date_value, datetime):
        return date_value.strftime(format)
    return date_value

# This function is a utility to extract certain keys from a dictionary
def extract_keys(data, keys):
    """
    Extracts specified keys from a dictionary.

    Parameters:
    data (dict): The dictionary from which to extract data.
    keys (list): The keys to extract from the dictionary.

    Returns:
    dict: A dictionary containing the extracted keys and their corresponding values.
        If a key is not present in the input dictionary, its value in the output dictionary will be an empty dictionary.
    """
    return {key: data.get(key, {}) for key in keys}

# This function serializes vulnerability data for easier consumption by the client
def serialize_all_vulnerability(vulnerability):
    # Extract the 'GSD' and 'namespaces' keys from the vulnerability data
    data = extract_keys(vulnerability, ['GSD', 'namespaces'])
    # Return a dictionary with the serialized data
    return {
        # Convert the '_id' field to a string and store it as 'cveID'
        'cveID': str(vulnerability["_id"]),
        # Extract the 'description' field from the 'GSD' data, or use an empty string if it's not present
        'description': data['GSD'].get('description', ''),
        # Extract the 'references' field from the 'GSD' data, or use an empty list if it's not present
        'references': data['GSD'].get('references', []),
        # Extract the 'cisa.gov' namespace data, or use an empty dictionary if it's not present
        'cisaData': data['namespaces'].get('cisa.gov', {}),
        # Extract the 'cve.org' namespace data, or use an empty dictionary if it's not present
        'cve.Org': data['namespaces'].get('cve.org', {}),
        # Extract the 'nvd.nist.gov' namespace data, or use an empty dictionary if it's not present
        'nvdData': data['namespaces'].get('nvd.nist.gov', {})
    }

# Serializer for NVD vulnerability data
def nvd_serializer(vulnerability):
    nvd_data = extract_keys(vulnerability.get("namespaces", {}), ["nvd.nist.gov"])
    return {
        'cveID': str(vulnerability["_id"]),
        'nvdData': nvd_data["nvd.nist.gov"]
    }

# Serializer for MITRE vulnerability data
def mitre_serializer(vulnerability):
    mitre_data = extract_keys(vulnerability.get("namespaces", {}), ["cve.org"])
    return {
        'cveID': str(vulnerability["_id"]),
        'mitreData': mitre_data["cve.org"]
    }

# This function serializes vulnerability data for easier consumption by the client
def serialize_vulnerability(vulnerability):
    """
    Serializes a vulnerability dictionary into a more manageable format.

    Parameters:
    vulnerability (dict): The vulnerability data to be serialized.

    Returns:
    dict: A dictionary containing the serialized vulnerability data.
    """
    # First, serialize the fields that you want at the top
    # Convert the '_id' field to a string and store it as '_id'
    # Store the 'cveID', 'dateAdded', and 'dueDate' fields as they are
    serialized_data = {
        '_id': str(vulnerability["_id"]),
        'cveID': vulnerability["cveID"],
        'dateAdded': serialize_date(vulnerability.get("dateAdded")),
        'dueDate': serialize_date(vulnerability.get("dueDate"))
    }
    
    # Define the other fields that you want to extract from the vulnerability data
    fields_to_extract = [
        'notes', 'product', 'requiredAction', 'shortDescription', 
        'vendorProject', 'vulnerabilityName', 'nvdData', 
        'githubPocs', 'openThreatData', 'knownRansomwareCampaignUse'
    ]
    # Extract these fields and update the serialized data dictionary with them
    serialized_data.update(extract_keys(vulnerability, fields_to_extract))
    
    # Return the serialized data
    return serialized_data

# Define serializers for returning the cve and githubpocs
def serialize_githubpocs(vulnerability):
    return {
        'cveID': vulnerability["cveID"],
        "githubPocs": vulnerability.get("githubPocs", None)
    }

def serialize_recent_cve_vulnerability(vulnerability):
    """
    Serializes a recent CVE vulnerability dictionary into a more manageable format.

    Parameters:
    vulnerability (dict): The recent CVE vulnerability data to be serialized.

    Returns:
    dict: A dictionary containing the serialized recent CVE vulnerability data.
    """
    # Return a dictionary with the serialized data
    return {
        # Store the '_id' field as it is
        "_id": vulnerability["_id"],
        # Convert the 'pubDateKev' and 'pubModDateKev' fields to ISO format
        "pubDateKev": vulnerability["pubDateKev"].isoformat(),
        "pubModDateKev": vulnerability["pubModDateKev"].isoformat(),
        # Extract the 'nvdData' field from the vulnerability data, or use None if it's not present
        "nvdData": vulnerability.get("nvdData", None)
    }
