# KEVin

The missing API for CISA's Known Exploited Vulnerabilities Catalog ([here](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)).

## Public Host

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
PUBLIC_BASE_URL=https://kevin.gtfkd.com
TRUSTED_HOSTS=kevin.gtfkd.com,localhost,127.0.0.1
ORIGIN_RATE_LIMIT_WINDOW_SECONDS=1
UNCACHED_QUERY_RATE_LIMIT=10
POINT_MISS_RATE_LIMIT=20
NEGATIVE_CACHE_TIMEOUT=15
NEGATIVE_CACHE_MAX_ENTRIES=1024
CACHE_SINGLEFLIGHT_WAIT_SECONDS=0
CACHE_FILL_LOCK_SECONDS=15
CACHE_TTL_JITTER_RATIO=0.1
```

Feel free to edit the mongodb in use or variable names. I have both in here since I work on prod and dev mongodbs for the hosted version of KEVin at kevin.gtfkd.com/*.

`PUBLIC_BASE_URL` is the canonical public origin used in homepage metadata.
`TRUSTED_HOSTS` is a comma-separated allowlist for accepted HTTP Host headers;
include the hostname used by local health checks and reverse proxies.

The origin-admission settings are read once at startup. Redis enforces the
shared per-window limits across workers: `UNCACHED_QUERY_RATE_LIMIT` covers
list and recent-KEV cache misses, and `POINT_MISS_RATE_LIMIT` covers point,
RSS, and metrics misses. Cached 2xx and 4xx responses share the same TTL.
Fill locks (`CACHE_FILL_LOCK_SECONDS`) serialize origin work across workers
with owner tokens, `CACHE_SINGLEFLIGHT_WAIT_SECONDS` defaults to 0 so a
contended key fails immediately, and `CACHE_TTL_JITTER_RATIO` spreads expiry with `secrets.randbelow`.
High-cardinality `/kev` search and actor variants stay out of Redis; exact
repeats use a bounded in-process cache.
Manual point resources also keep at most `NEGATIVE_CACHE_MAX_ENTRIES`
short-lived local misses as an L1 cache in front of Redis.

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
