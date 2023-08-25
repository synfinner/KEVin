#!/usr/bin/env python3

#setup pymongo import
from pymongo import MongoClient
#setup requests import
import requests

#load env using python-dotenv
from dotenv import load_dotenv
load_dotenv()
#get the api_key from the loaded env
import os
from time import sleep

api_key = os.getenv("API_KEY")


#mongodb config
MONGO_URI = "mongodb://localhost:27017/"
DB_NAME = "kev"
COLLECTION_NAME = "vulns"


# function for getting nvd data
def get_nvd_data(cve_id):
    base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    cve_url = f"{base_url}?cveId={cve_id}"
    headers = {
        "User-Agent": "KEVinAPI",  # Replace with your user agent
        "apiKey": api_key
    }
    response = requests.get(cve_url, headers=headers)
    if response.status_code == 200:
        cve_data = response.json()
        return cve_data
    else:
        print(f"Failed to retrieve data for CVE {cve_id}")
        return None

# function for processing nvd data
def nvd_processor():
    # Connect to MongoDB
    client = MongoClient(MONGO_URI)
    db = client[DB_NAME]
    collection = db[COLLECTION_NAME]

    # iterate through each document in the mongo collection
    for vulnerability in collection.find():
        # check if the document has a "nvdData" array in the json object or if the nvdData array is empty
        if "nvdData" not in vulnerability or len(vulnerability["nvdData"]) == 0:
            # if nvdData does not exist, call the get_nvd_data function and pass the cveID
            print("[+] Calling get_nvd_data for " + vulnerability["cveID"])
            nvd_data = get_nvd_data(vulnerability["cveID"])
            # if the nvd_data is not None, add the nvdData to the mongo document
            if nvd_data:
                try:
                    vuln_data = nvd_data["vulnerabilities"][0]["cve"]
                except:
                    # skip this vuln as it does not have nvd data
                    continue
                # if baseScore not in vuln_data, continue to the next object. This is because NVD is "analyzing" and data isn't available yet
                if "baseScore" not in vuln_data:
                    continue
                nvd_data_array = []  # Initialize an empty array
                try:
                    cvss_metrics_v31 = vuln_data["metrics"]["cvssMetricV31"][0]["cvssData"]
                    # Extract desired fields and append them to the array
                    nvd_data_array.append({
                        "attackVector": cvss_metrics_v31["attackVector"],
                        "attackComplexity": cvss_metrics_v31["attackComplexity"],
                        "baseSeverity": cvss_metrics_v31["baseSeverity"],
                        "exploitabilityScore": vuln_data["metrics"]["cvssMetricV31"][0]["exploitabilityScore"],
                        "baseScore": cvss_metrics_v31["baseScore"]
                    })
                except:
                    # fall back to cvss2 if cvss3 is not available
                    cvss_metrics_v2 = vuln_data["metrics"]["cvssMetricV2"][0]["cvssData"]
                    nvd_data_array.append({
                        "attackVector": cvss_metrics_v2["accessVector"],
                        "attackComplexity": cvss_metrics_v2["accessComplexity"],
                        "baseSeverity": vuln_data["metrics"]["cvssMetricV2"][0]["baseSeverity"],
                        "exploitabilityScore": vuln_data["metrics"]["cvssMetricV2"][0]["exploitabilityScore"],
                        "baseScore": cvss_metrics_v2["baseScore"]
                    })
                finally:
                    # Update the nvdData array in the mongo document
                    collection.update_one(
                        {"cveID": vulnerability["cveID"]},
                        {"$set": {"nvdData": nvd_data_array}}
                    )
            else:
                # If the nvd_data is None, set the nvdData array to an empty array
                nvd_data_array = []
                collection.update_one(
                    {"cveID": vulnerability["cveID"]},
                    {"$set": {"nvdData": nvd_data_array}}
                )
                # add the nvdData to the mongo document as
            #Print the cve id we added nvd data to
            print("[+] Added nvdData to " + vulnerability["cveID"])
            # nvd rate limit
            sleep(3)
    #close mongodb connection
    client.close()
        
def main():
    nvd_processor()

if __name__ == "__main__":
    main()