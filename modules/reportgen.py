# create report gen function that will receive the vulnerability data from class vulnerabilityReport(Resource)
def report_gen(vulnerability):
    # build variables that will be used in the markdown report
    cve_id = vulnerability['_id']
    
    # Check if cisa.gov is present in namespaces
    if 'cisa.gov' in vulnerability['namespaces']:
        cisa_data = vulnerability['namespaces']['cisa.gov']
        cisa_required_action = cisa_data['requiredAction']
    else:
        cisa_data = None
    
    nvd_data = vulnerability['namespaces']['nvd.nist.gov']
    vuln_description = nvd_data['cve']['description']['description_data'][0]['value']
    # Check if cve.Org is present and has product data
    versions_text = ""
    cve_org_data = vulnerability['namespaces']['cve.org']
    vendor_data = cve_org_data['affects']['vendor']['vendor_data']
    for vendor in vendor_data:
        product_data = vendor['product']['product_data']
        for product in product_data:
            if 'version' in product:
                version_data = product['version']['version_data']
                vulnerable_versions = [version['version_value'] for version in version_data]
                versions_text += "\n".join([f"- {version}" for version in vulnerable_versions])
    # Add the text snippet before the vulnerable versions
    if versions_text:
        versions_text = "The following versions have been identified as being vulnerable:\n\n" + versions_text
    
    # Array storage for references
    vuln_references = [] 
    for reference_url in nvd_data['cve']['references']['reference_data']:
        if reference_url['url'] != '':
            if reference_url['url'] not in vuln_references:
                vuln_references.append(reference_url['url'])
    
    # Build the markdown report with version data included in description
    references_bullet_points = '\n'.join([f"- {ref}" for ref in vuln_references])
    report = f"""

## Description

{vuln_description}

{versions_text}
"""

    # Include Remediation section if cisa_data is not None
    if cisa_data:
        cisa_remediation = cisa_required_action
        report += f"""

## Remediation

{cisa_remediation}
"""
    
    # Add References section
    report += f"""

## References

{references_bullet_points}
"""
    
    return report
