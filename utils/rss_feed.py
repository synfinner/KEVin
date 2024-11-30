import html
from defusedxml import ElementTree
from xml.etree.ElementTree import Element, SubElement

def create_rss_feed(recent_entries):
    # Create the root element for the RSS feed
    rss = Element("rss", version="2.0")
    channel = SubElement(rss, "channel")
    SubElement(channel, "title").text = "Recent KEV Entries"
    SubElement(channel, "link").text = "https://kevin.gtfkd.com/rss"
    SubElement(channel, "description").text = "Latest entries from the KEVin API for Known Exploited Vulnerabilities."

    # Add Atom link for self-reference
    atom_link = SubElement(channel, "{http://www.w3.org/2005/Atom}link")
    atom_link.set("rel", "self")
    atom_link.set("href", "https://kevin.gtfkd.com/rss")

    for entry in recent_entries:
        item = SubElement(channel, "item")
        SubElement(item, "title").text = f"{entry.get('cveID', 'No CVE ID')} - {entry.get('vulnerabilityName', 'No Title')}"
        
        # Handle dateAdded correctly
        date_added = entry.get("dateAdded")
        if isinstance(date_added, str):
            from dateutil import parser
            date_added = parser.parse(date_added)
        
        SubElement(item, "pubDate").text = date_added.strftime("%a, %d %b %Y %H:%M:%S +0000") if date_added else "No Date"
        
        # Add a link element for the NVD URL
        nvd_url = f"https://nvd.nist.gov/vuln/detail/{entry.get('cveID', 'No CVE ID')}"
        SubElement(item, "link").text = nvd_url
        
        guid = SubElement(item, "guid")
        guid.text = nvd_url
        guid.set("isPermaLink", "true")

        # Add description with additional information
        description_html = f"""
        <p><strong>CVE:</strong> {html.escape(entry.get('cveID', 'No CVE ID'))}</p>
        <p><strong>Description:</strong> {html.escape(entry.get('shortDescription', 'No Description'))}</p>
        <ul>
            <li><strong>Known Ransomware Usage:</strong> {entry.get('knownRansomwareCampaignUse', 'No Known Ransomware Usage')}</li>
            <li><strong>GitHub POCs:</strong>
                <ul>
        """

        # Handle lists for GitHub POCs
        github_pocs = entry.get("githubPocs", [])
        if isinstance(github_pocs, list) and github_pocs:
            for poc in github_pocs:
                description_html += f"<li>{poc}</li>"
        else:
            description_html += "<li>No GitHub POCs</li>"

        description_html += "</ul></li></ul>"

        open_threat_data = entry.get("openThreatData", [])
        if isinstance(open_threat_data, list) and open_threat_data:
            adversaries = []
            affected_industries = []
            for data in open_threat_data:
                adversaries.extend(data.get("adversaries", []))
                affected_industries.extend(data.get("affectedIndustries", []))
            
            adversaries_str = ", ".join(set(adversaries)) if adversaries else "No Adversaries"
            affected_industries_str = ", ".join(set(affected_industries)) if affected_industries else "No Affected Industries"
            open_threat_data_html = f"""
            <ul>
                <li><strong>Adversaries:</strong> {adversaries_str}</li>
                <li><strong>Affected Industries:</strong> {affected_industries_str}</li>
            </ul>
            """
        else:
            open_threat_data_html = "<p>No Open Threat Data</p>"

        # Combine all parts into the description
        full_description = description_html + open_threat_data_html
        SubElement(item, "description").text = full_description

        # Add category
        SubElement(item, "category").text = "Vulnerability"

    rss_feed = ElementTree.tostring(rss, encoding='utf-8', method='xml')
    return rss_feed