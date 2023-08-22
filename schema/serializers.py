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
    
    # Construct the serialized vulnerability dictionary
    serialized_vulnerability = {
        '_id': str(vulnerability["_id"]),
        'cveID': vulnerability["cveID"],
        'dateAdded': date_added_str,
        'dueDate': due_date_str,
        'notes': vulnerability["notes"],
        'product': vulnerability["product"],
        'requiredAction': vulnerability["requiredAction"],
        'shortDescription': vulnerability["shortDescription"],
        'vendorProject': vulnerability["vendorProject"],
        'vulnerabilityName': vulnerability["vulnerabilityName"]
    }
    
    return serialized_vulnerability
