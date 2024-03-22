from jinja2 import Template

def get_cisa_data(vulnerability):
    return vulnerability['namespaces'].get('cisa.gov', None)

def get_nvd_data(vulnerability):
    return vulnerability['namespaces'].get('nvd.nist.gov', {})

def get_vulnerable_versions(vulnerability):
    versions_text = ""
    cve_org_data = vulnerability['namespaces'].get('cve.org', {})
    vendor_data = cve_org_data.get('affects', {}).get('vendor', {}).get('vendor_data', [])
    for vendor in vendor_data:
        product_data = vendor.get('product', {}).get('product_data', [])
        for product in product_data:
            if 'version' in product:
                version_data = product['version'].get('version_data', [])
                vulnerable_versions = [version['version_value'] for version in version_data]
                versions_text += "\n".join([f"- {version}" for version in vulnerable_versions])
    return versions_text

def get_vuln_references(nvd_data):
    vuln_references = [] 
    for reference_url in nvd_data.get('cve', {}).get('references', {}).get('reference_data', []):
        if reference_url['url'] != '':
            if reference_url['url'] not in vuln_references:
                vuln_references.append(reference_url['url'])
    return vuln_references

def report_gen(vulnerability):
    cisa_data = get_cisa_data(vulnerability)
    nvd_data = get_nvd_data(vulnerability)
    versions_text = get_vulnerable_versions(vulnerability)
    vuln_references = get_vuln_references(nvd_data)

    report_template = Template("""
## Description

{{vuln_description}}

{{versions_text}}

{% if cisa_data %}
## Remediation

{{cisa_remediation}}

{% endif %}
## References

{{references_bullet_points}}
""")

    report = report_template.render(
        vuln_description=nvd_data.get('cve', {}).get('description', {}).get('description_data', [{}])[0].get('value', ''),
        versions_text=versions_text,
        cisa_data=cisa_data,
        cisa_remediation=cisa_data.get('requiredAction', '') if cisa_data else '',
        references_bullet_points='\n'.join([f"- {ref}" for ref in vuln_references])
    )

    return report
