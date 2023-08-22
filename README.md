# KEVin

The missing API for CISA's Known Exploited Vulnerabilities Catalog ([here](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)).

## Features

- Fetch vulnerability details by CVE ID
- Retrieve a list of all vulnerabilities
- Get new vulnerabilities added in the last X days

## Setup

- `python3 -m venv env`
- `source env/bin/activate`
- `pip3 install -r requirements.txt`

**Set up MongoDB:**

- Install MongoDB: [MongoDB Installation Guide](https://www.mongodb.com/docs/manual/installation/)
- Start MongoDB server
- Configure MongoDB details in kevin.py:


**Run update.py**

`update.py` will pull data from CISA and populate your mongodb. Enjoy.

## Usage

- Fetch KEV entries by CVE: `/kev/CVE-2023-1234`
- Retrieve all KEV entries: `/kev`
- Get new vulns added in the last X days: `/kev/new/7`

## Considerations

**You should not expose mongodb to the broader internet.**

## Contributing

Contributions are welcome! If you find any issues or have ideas for improvements, please feel free to open an issue or submit a pull request. I won't have a whole lot of time to improve this at the moment