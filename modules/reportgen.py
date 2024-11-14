from jinja2 import Template

def get_nvd_data(vulnerability):
    return vulnerability['namespaces'].get('nvd_nist_gov', {})

def get_vulnerable_versions(vulnerability):
    versions_text = ""
    cve_org_data = vulnerability['namespaces'].get('nvd_nist_gov', {}).get('cve', {})
    return versions_text

def get_vuln_references(nvd_data):
    vuln_references = [] 
    for reference_url in nvd_data.get('cve', {}).get('references', []):
        if reference_url['url'] != '':
            if reference_url['url'] not in vuln_references:
                vuln_references.append(reference_url['url'])
    return vuln_references

def get_vuln_description(nvd_data):
    descriptions = nvd_data.get('cve', {}).get('descriptions', [])
    for desc in descriptions:
        if desc.get('lang') == 'en':
            return desc.get('value', '')
    return ''  # Return empty string if no English description is found

def get_cvss_metrics(nvd_data):
    cvss_data = []
    
    # Extract CVSS v3.1 data
    cvss_v31 = nvd_data.get('cve', {}).get('metrics', {}).get('cvssMetricV31', [])
    for metric in cvss_v31:
        cvss_info = metric.get('cvssData', {})
        cvss_data.append({
            "version": "3.1",
            "baseScore": cvss_info.get("baseScore", "N/A"),
            "baseSeverity": cvss_info.get("baseSeverity", "N/A"),
            "vectorString": cvss_info.get("vectorString", "N/A"),
            "attackComplexity": cvss_info.get("attackComplexity", "N/A"),
            "attackVector": cvss_info.get("attackVector", "N/A"),
        })
    
    # Extract CVSS v4.0 data
    cvss_v40 = nvd_data.get('cve', {}).get('metrics', {}).get('cvssMetricV40', [])
    for metric in cvss_v40:
        cvss_info = metric.get('cvssData', {})
        cvss_data.append({
            "version": "4.0",
            "baseScore": cvss_info.get("baseScore", "N/A"),
            "baseSeverity": cvss_info.get("baseSeverity", "N/A"),
            "vectorString": cvss_info.get("vectorString", "N/A"),
            "attackComplexity": cvss_info.get("attackComplexity", "N/A"),
            "attackVector": cvss_info.get("attackVector", "N/A"),
        })
    
    return cvss_data

def report_gen(vulnerability):
    nvd_data = get_nvd_data(vulnerability)
    versions_text = get_vulnerable_versions(vulnerability)
    vuln_references = get_vuln_references(nvd_data)
    vuln_description = get_vuln_description(nvd_data)
    cvss_metrics = get_cvss_metrics(nvd_data)

    # Updated Jinja2 template
    report_template = Template("""
## Description

{{ vuln_description }}

{{ versions_text }}

## CVSS Metrics

{% for metric in cvss_metrics %}
- **Version**: {{ metric.version }}
- **Base Score**: {{ metric.baseScore }}
- **Severity**: {{ metric.baseSeverity }}
- **Vector String**: {{ metric.vectorString }}
- **Attack Complexity**: {{ metric.attackComplexity }}
- **Attack Vector**: {{ metric.attackVector }}

{% endfor %}

## References

{{ references_bullet_points }}
""")

    report = report_template.render(
        vuln_description=vuln_description,
        versions_text=versions_text,
        references_bullet_points='\n'.join([f"- {ref}" for ref in vuln_references]),
        cvss_metrics=cvss_metrics
    )

    return report