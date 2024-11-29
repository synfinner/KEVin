from bson import ObjectId
from datetime import datetime
import json

class jencoder(json.JSONEncoder):
    """
    Custom JSON Encoder to handle ObjectId and datetime serialization.
    """
    def default(self, obj):
        if isinstance(obj, ObjectId):
            return str(obj)  # Convert ObjectId to string
        if isinstance(obj, datetime):
            return obj.isoformat()  # Convert datetime to ISO format
        return super().default(obj)