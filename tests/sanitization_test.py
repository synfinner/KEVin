#!/usr/bin/env python3

import pytest
from kevin import sanitize_query
from schema.api import sanitize_query as api_sanitize_query

def test_sanitize_query():
    assert sanitize_query("abc123") == "abc123"
    assert sanitize_query("abc 123") == "abc 123"
    assert sanitize_query("abc-123") == "abc-123"
    assert sanitize_query("abc@123") == "abc123"
    assert sanitize_query(None) == None
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
    assert sanitize_query("1; DROP TABLE users") == "1 DROP TABLE users"
    assert sanitize_query("admin' --") == "admin --"
    assert sanitize_query("<a href='http://example.com' target='_blank'>Link</a>") == "a hrefhttpexamplecom targetblankLinka"

    # Test for double URL encoded values
    assert sanitize_query("%253Cscript%253E") == "script"
    assert sanitize_query("%2520") == ""

def test_api_sanitize_query():
    assert api_sanitize_query("abc123") == "abc123"
    assert api_sanitize_query("abc 123") == "abc 123"
    assert api_sanitize_query("abc-123") == "abc-123"
    assert api_sanitize_query("abc@123") == "abc123"
    assert api_sanitize_query(None) == None
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
    assert api_sanitize_query("1; DROP TABLE users") == "1 DROP TABLE users"
    assert api_sanitize_query("admin' --") == "admin --"
    assert api_sanitize_query("<a href='http://example.com' target='_blank'>Link</a>") == "a hrefhttpexamplecom targetblankLinka"

    # Test for double URL encoded values
    assert api_sanitize_query("%253Cscript%253E") == "script"
    assert api_sanitize_query("%2520") == ""