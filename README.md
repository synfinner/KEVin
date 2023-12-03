# KEVin

The missing API for CISA's Known Exploited Vulnerabilities Catalog ([here](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)).

## Hosted Instance

I am currently hosting an instance of KEVin (with some extra features not included in this source). 

Accessing KEVin can be done so at https://kevin.gtfkd.com/

Rate limits are currently in place and caching is set to 3 hours at the edge.

### Status

To check the status of the hosted instance, please refer to our statuspage: https://kevinapi.statuspage.io/

## Features

- Fetch vulnerability details by CVE ID
- Retrieve a list of all vulnerabilities
- Get new vulnerabilities added in the last X days

## Setup

- `python3 -m venv env`
- `source env/bin/activate`
- `pip3 install -r requirements.txt`

### Add .env

Add necessary API KEYS. 

- API_KEY = nvd api key -- [Obtained here](https://nvd.nist.gov/developers/request-an-api-key)

```
API_KEY=xxx
MONGODB_URI_PROD=mongodb://MONGO_PROD_IP:27017/
MONGODB_URI_DEV=mongodb://localhost:27017/
```

Feel free to edit the mongodb in use or variable names. I have both in here since I work on prod and dev mongodbs for the hosted version of KEVin at kevin.gtfkd.com/*.

**Set up MongoDB:**

- Install MongoDB: [MongoDB Installation Guide](https://www.mongodb.com/docs/manual/installation/)
- Start MongoDB server
- Configure MongoDB details in kevin.py:

**Run update.py**

`update.py` will pull data from CISA and populate your mongodb. Enjoy.

## Deploying to docker

Below is an example docker-compose.yml file for deploying the web half of KEVin.

**make sure your .env file has the correct values!!!**

```
version: '3'
services:
  flask_app:
    build:
      context: .  # The build context is now the KEVin folder
      dockerfile: Dockerfile  # Use the Dockerfile we created inside KEVin
    container_name: KEVin
    env_file:
      - .env
    networks:
      - gtfkdProd
    ports:
      - "8444:8444"  # Map host port to container port
    restart: unless-stopped
networks:
  gtfkdProd:
    external: true
```

## Usage

- Fetch KEV entries by CVE: `/kev/CVE-2023-1234`
- Retrieve all KEV entries: `/kev`
- Get new vulns added in the last X days: `/kev/new/7`
- Pull CISA, MITRE, NVD data for a CVE: `/vuln/<string:cve_id>`
- Pull just NVD data for a CVE: `/vuln/<string:cve_id>/nvd`
- Text search KEV data `/kev?search=Microsoft`

## Considerations

**You should not expose mongodb to the broader internet.**

## Contributing

Contributions are welcome! If you find any issues or have ideas for improvements, please feel free to open an issue or submit a pull request. I won't have a whole lot of time to improve this at the moment