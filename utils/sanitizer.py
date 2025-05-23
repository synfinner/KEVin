import re
import unicodedata
from urllib.parse import unquote

# Pre-compile regex patterns for sanitizing input to improve performance
ALNUM_SPACE_HYPHEN_UNDERSCORE_RE = re.compile(r"[^\w\s-]+", re.UNICODE)
EXTRA_WHITESPACE_RE = re.compile(r"\s+", re.UNICODE)
CVE_RE = re.compile(r"\bcve\b", re.IGNORECASE)
# SQL Injection patterns - optimized for performance and reduced false positives
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
    r")\b)|("
    # Common dangerous SQL functions with word boundaries
    r"\b(CONCAT|SLEEP|BENCHMARK|WAITFOR)\b|"
    # Comment markers with limited scope
    r";\s*--|;\s*#|"
    r"\/\*[^\*]{0,50}\*\/|"
    r"--[^\r\n]{0,50}|"
    r"#[^\r\n]{0,50}|"
    # Common attack patterns with bounded scope
    r"'\s*OR\s*'\s*=\s*'|"
    r"'\s*OR\s*1\s*=\s*1|"
    r"'\s*OR\s*'1'\s*=\s*'1|"
    # Split keywords - more precise patterns
    r"\bSEL\s*[_\s]\s*ECT\b|"
    r"\bUNI\s*[_\s]\s*ON\b|"
    r"\bEXE\s*[_\s]\s*C\b"
    r")",
    re.IGNORECASE
)

# NoSQL Injection patterns - optimized for performance and reduced false positives
NOSQL_INJECTION_RE = re.compile(
    r"(\b("
    # Common MongoDB operators - most frequently used in attacks
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
    r"\$elemMatch"
    r")\b)|("
    # Additional MongoDB operators with specific context
    r"\$\w+\s*:\s*\/|"
    r"\$\w+\s*:\s*function\s*\(|"
    # JavaScript injection patterns
    r"function\s*\([^)]{0,30}\)\s*\{|"
    r"eval\s*\([^)]{0,30}\)|"
    r"new\s+Function\s*\(|"
    r"setTimeout\s*\(|"
    r"setInterval\s*\(|"
    # Object injection with context
    r"\{\s*\$\w+\s*:\s*\{[^}]{0,50}|"
    r"\{\s*\$\w+\s*:\s*\[[^\]]{0,50}|"
    # JavaScript execution contexts
    r"\$\w+\s*:\s*Math\.|"
    r"\$\w+\s*:\s*Date\.|"
    r"\$\w+\s*:\s*JSON\.|"
    r"\$\w+\s*:\s*Object\."
    r")",
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