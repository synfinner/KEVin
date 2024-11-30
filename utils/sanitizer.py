import re
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
    r";|--"
    r")\b)",
    re.IGNORECASE
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
    # Check if the query is None and length check
    if query is None:
        return None

    query = str(query).strip()
    if len(query) > 50:
         return None
    
    # URL decode iteratively
    for _ in range(5):  # Limit the number of iterations to prevent infinite loops
        try:
            decoded_query = unquote(query)
            if decoded_query == query:
                break
            query = decoded_query
        except Exception:  # Catch any exceptions that may occur during URL decoding
            return None  # Return None if decoding fails
    
    # allowed characters (alphanumeric, spaces, hyphens)
    query = ALNUM_SPACE_HYPHEN_UNDERSCORE_RE.sub('', query)

    # Normalize occurrences of "cve" to "CVE"
    query = CVE_RE.sub('CVE', query)

    # Replace multiple spaces with a single space
    query = EXTRA_WHITESPACE_RE.sub(' ', query).strip()

    # Check for potential SQL injection patterns
    if SQL_INJECTION_RE.search(query):
        return None

    return query