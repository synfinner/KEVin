import re
import unicodedata
from urllib.parse import unquote

# Pre-compile regex patterns for sanitizing input to improve performance
ALNUM_SPACE_HYPHEN_UNDERSCORE_RE = re.compile(r"[^\w\s-]+", re.UNICODE)
EXTRA_WHITESPACE_RE = re.compile(r"\s+", re.UNICODE)
CVE_RE = re.compile(r"\bcve\b", re.IGNORECASE)
SQL_INJECTION_RE = re.compile(
    r"(\b("
    r"SELECT|"
    r"INSERT|"
    r"UPDATE|"
    r"DELETE|"
    r"DROP|"
    r"CREATE|"
    r"ALTER|"
    r"TRUNCATE|"
    r"EXEC|"
    r"UNION|"
    r"CONCAT|"
    r"CHAR|"
    r"SUBSTRING|"
    r"SLEEP|"
    r"BENCHMARK|"
    r"WAITFOR|"
    r"DELAY|"
    r"INFORMATION_SCHEMA|"
    r"LOAD_FILE|"
    r"CAST|"
    r"CONVERT|"
    r"DECLARE|"
    r"DBMS_|"
    r")\b)|("
    r";\s*--|"
    r";\s*#|"
    r"\/\*.*?\*\/|"
    r"--.*?$|"
    r"#.*?$|"
    r"'\s*OR\s*'\s*'\s*=|"
    r"'\s*OR\s*[0-9]\s*=|"
    r"'\s*OR\s*[a-zA-Z]\s*=|"
    r"\\x[0-9a-fA-F]+|"
    r"\s+AND\s+[0-9]\s*=|"
    r"\s+OR\s+[0-9]\s*=|"
    r"\s+AND\s+[a-zA-Z]\s*=|"
    r"\s+OR\s+[a-zA-Z]\s*=|"
    r"\s+IS\s+NULL|"
    r"\s+IS\s+NOT\s+NULL|"
    r"\s+LIKE\s+['\"][%_]|"
    r"\s+IN\s*\(\s*['\"]|"
    r"\bSEL\s*[\W_]+\s*ECT|"
    r"\bUNI\s*[\W_]+\s*ON|"
    r"\bEXE\s*[\W_]+\s*C|"
    r"\bUPD\s*[\W_]+\s*ATE"
    r")",
    re.IGNORECASE | re.DOTALL
)

# NoSQL Injection patterns
NOSQL_INJECTION_RE = re.compile(
    r"(\b("
    r"\$where|"
    r"\$regex|"
    r"\$ne|"
    r"\$gt|"
    r"\$lt|"
    r"\$gte|"
    r"\$lte|"
    r"\$in|"
    r"\$nin|"
    r"\$and|"
    r"\$or|"
    r"\$not|"
    r"\$nor|"
    r"\$exists|"
    r"\$elemMatch|"
    r"\$push|"
    r"\$pull|"
    r"\$addToSet|"
    r"\$pop|"
    r"\$group|"
    r"\$match|"
    r"\$project|"
    r"\$lookup|"
    r"\$unwind|"
    r"\$sort|"
    r"\$limit|"
    r"\$skip|"
    r"\$count|"
    r"\$sum|"
    r"\$avg|"
    r"\$max|"
    r"\$min|"
    r"\$expr|"
    r"\$cond|"
    r"\$ifNull|"
    r"\$switch|"
    r"\$map|"
    r"\$reduce|"
    r"\$filter|"
    r"\{\s*\$|"
    r"\$\s*:\s*"
    r")\b)|("
    r"\{\s*\$\w+\s*:\s*\{|"
    r"\{\s*\$\w+\s*:\s*\[|"
    r"\{\s*\$\w+\s*:\s*\/|"
    r"\{\s*\$\w+\s*:\s*function|"
    r"function\s*\(|"
    r"eval\s*\(|"
    r"new\s+Function|"
    r"setTimeout|"
    r"setInterval|"
    r"\{\s*\$\w+\s*:\s*true|"
    r"\{\s*\$\w+\s*:\s*false|"
    r"\{\s*\$\w+\s*:\s*null|"
    r"\{\s*\$\w+\s*:\s*undefined|"
    r"\{\s*\$\w+\s*:\s*NaN|"
    r"\{\s*\$\w+\s*:\s*Infinity|"
    r"\{\s*\$\w+\s*:\s*-Infinity|"
    r"\{\s*\$\w+\s*:\s*new\s+|"
    r"\{\s*\$\w+\s*:\s*Math\.|"
    r"\{\s*\$\w+\s*:\s*Date\.|"
    r"\{\s*\$\w+\s*:\s*JSON\.|"
    r"\{\s*\$\w+\s*:\s*Object\.|"
    r"\{\s*\$\w+\s*:\s*Array\.|"
    r"\{\s*\$\w+\s*:\s*String\.|"
    r"\{\s*\$\w+\s*:\s*Number\.|"
    r"\{\s*\$\w+\s*:\s*Boolean\.|"
    r"\{\s*\$\w+\s*:\s*RegExp\."
    r")",
    re.IGNORECASE | re.DOTALL
)

# Function for sanitizing input
def sanitize_query(query):
    """
    Sanitize the input query to prevent malicious input.

    This function checks and sanitizes the provided query string by:
    - Returning None if the query is None or exceeds a specified length.
    - Iteratively URL decoding the query to handle encoded characters.
    - Whitelisting allowed characters (alphanumeric, spaces, hyphens, underscores).
    - Normalizing occurrences of "cve" to "CVE".
    - Replacing multiple spaces with a single space.
    - Checking for potential SQL injection patterns and returning None for suspicious queries.

    Parameters:
    query (str): The input query string to sanitize.

    Returns:
    str or None: The sanitized query string if valid, or None if the input is invalid or suspicious.
    """
    # Check if the query is None
    if query is None:
        return None

    # Convert the query to string and remove leading/trailing whitespace
    query = str(query).strip()
    
    # URL decode iteratively
    for _ in range(5):  # Limit the number of iterations to prevent infinite loops
        try:
            decoded_query = unquote(query)
            if decoded_query == query:
                break
            query = decoded_query
        except Exception:  # Catch any exceptions that may occur during URL decoding
            return None  # Return None if decoding fails
    
    # Normalize Unicode to prevent homoglyph attacks
    query = unicodedata.normalize('NFKC', query)
    
    # allowed characters (alphanumeric, spaces, hyphens)
    query = ALNUM_SPACE_HYPHEN_UNDERSCORE_RE.sub('', query)

    # Normalize occurrences of "cve" to "CVE"
    query = CVE_RE.sub('CVE', query)

    # Replace multiple spaces with a single space
    query = EXTRA_WHITESPACE_RE.sub(' ', query).strip()

    # If the sanitized query exceeds the length limit, return None
    if len(query) > 50:
        return None

    # Check for potential SQL injection patterns
    if SQL_INJECTION_RE.search(query):
        return None
        
    # Check for potential NoSQL injection patterns
    if NOSQL_INJECTION_RE.search(query):
        return None

    return query