#!/usr/bin/env python3
"""Tests for shared query sanitization behavior."""

from kevin import sanitize_query
from schema.api import sanitize_query as api_sanitize_query

def test_sanitize_query():
    """Sanitize common inputs and reject suspicious SQL-like payloads."""
    assert sanitize_query("abc123") == "abc123"
    assert sanitize_query("abc 123") == "abc 123"
    assert sanitize_query("abc-123") == "abc-123"
    assert sanitize_query("abc@123") == "abc123"
    assert sanitize_query(None) is None
    assert sanitize_query(123) == "123"
    assert sanitize_query("CVE-1234-123456") == "CVE-1234-123456"
    assert sanitize_query("cve-1234-123456") == "CVE-1234-123456"

    # Test for potential MongoDB injection attacks
    assert sanitize_query("{$ne: null}") == "ne null"
    assert sanitize_query("{ $where: 'this.a > this.b' }") == "where thisa thisb"

    # Test for URL encoded values
    assert sanitize_query("%20") == ""
    assert sanitize_query("%3Cscript%3E") == "script"

    # Additional tests for malicious input
    assert sanitize_query("<img src='x' onerror='alert(1)'>") == "img srcx onerroralert1"
    assert sanitize_query("1; DROP TABLE users") is None
    assert sanitize_query("admin' --") == "admin --"
    link_payload = "<a href='http://example.com' target='_blank'>Link</a>"
    assert sanitize_query(link_payload) == "a hrefhttpexamplecom target_blankLinka"

    # Test for double URL encoded values
    assert sanitize_query("%253Cscript%253E") == "script"
    assert sanitize_query("%2520") == ""

def test_api_sanitize_query():
    """Apply the same sanitizer expectations through the API module export."""
    assert api_sanitize_query("abc123") == "abc123"
    assert api_sanitize_query("abc 123") == "abc 123"
    assert api_sanitize_query("abc-123") == "abc-123"
    assert api_sanitize_query("abc@123") == "abc123"
    assert api_sanitize_query(None) is None
    assert api_sanitize_query(123) == "123"
    assert api_sanitize_query("CVE-1234-123456") == "CVE-1234-123456"
    assert api_sanitize_query("cve-1234-123456") == "CVE-1234-123456"

    # Test for potential MongoDB injection attacks
    assert api_sanitize_query("{$ne: null}") == "ne null"
    assert api_sanitize_query("{ $where: 'this.a > this.b' }") == "where thisa thisb"

    # Test for URL encoded values
    assert api_sanitize_query("%20") == ""
    assert api_sanitize_query("%3Cscript%3E") == "script"

    # Additional tests for malicious input
    assert api_sanitize_query("<img src='x' onerror='alert(1)'>") == "img srcx onerroralert1"
    assert api_sanitize_query("1; DROP TABLE users") is None
    assert api_sanitize_query("admin' --") == "admin --"
    link_payload = "<a href='http://example.com' target='_blank'>Link</a>"
    assert api_sanitize_query(link_payload) == "a hrefhttpexamplecom target_blankLinka"

    # Test for double URL encoded values
    assert api_sanitize_query("%253Cscript%253E") == "script"
    assert api_sanitize_query("%2520") == ""
