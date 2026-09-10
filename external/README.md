<img src="../docs/SeverenceSMW.png"/>

# Severance: Secure SPARQL Service

# Installing the External Component

## Prerequisites

1. docker compose
2. A mechanism for generating an Auth token (or a pre-defined auth token)

## Configuration

1. create a new folder for your External server
2. create a ./data and ./queries-metadata file (as your own user, NOT ROOT!)
3. Copy the LATEST DOCKER COMPOSE FILE from the Severance ./external folder (this contains all patches)
4. Open the env_template file, edit it, and save it as .env in the same folder as the docker-compose file

### env_template

    ENCRYPTION_KEY_HEX=<generate with: openssl rand -hex 32>
    RESULT_FORMAT=csv                  # or "json"
    QUERY_DIR=/queries   # DO NOT CHANGE THIS unless you really know what you're doing
    QUEUE_DIR=/data/queue  # DO NOT CHANGE THIS unless you really know what you're doing
    RESULTS_DIR=/data/results  # DO NOT CHANGE THIS unless you really know what you're doing
    AUTH_TOKEN=YesItsMe
    ALLOWED_INTERNAL_IPS=172.31.0.1,127.0.0.1,::1,192.168.1.100   # CHANGE 192.168.1.100 to the IP of Internal 
    METADATA_DIR=/queries-metadata  # Don't change this unless you know what you're doing

`ALLOWED_INTERNAL_IPS` is a whitelist of addresses that are allowed to access the portions of the API that do not require authentication.  Each comma-separated entry may be a bare IP (`192.168.1.100`), a CIDR range (`192.168.1.0/24`), or the literal keyword `localhost`.  It should be VERY restrictive - maybe including localhost/127.0.0.1 only during testing

The `ENCRYPTION_KEY_HEX` must be shared with the external componenet, since all results are encrypted

**A note on what `AUTH_TOKEN` actually protects against:** it's a static, unsigned bearer value - anyone who ever obtains it (a leaked `.env`, a compromised client machine, a value exposed client-side, e.g. in a browser's own Network tab if a client handles it there) can replay it indefinitely, from anywhere, with no way for External to tell a legitimate client from a replay. Treat it as a basic filter against casual/accidental access, not as proof of *who* is really calling. What actually bounds the damage from a stolen token is Severance's named-query design: a stolen `AUTH_TOKEN` only ever lets someone submit one of the queries you've already pre-approved and installed on Internal, with attacker-chosen values for that query's own variables - never arbitrary SPARQL, never the query text itself. Choose what queries you install accordingly, and rotate `AUTH_TOKEN` if you ever suspect it's been exposed.


### docker-compose

    services:
        external:
            image: XXXXX  (the docker-compose in the Severance GitHub ./external folder points to the latest patch)
            restart: always
            security_opt:
                - "no-new-privileges:true"
            cap_drop:
                - ALL
            cap_add:
                # entrypoint.sh runs as root to chown the mounted volumes to the
                # severance user before dropping privileges via gosu -- these
                # are the only capabilities that step needs.
                - CHOWN
                - DAC_OVERRIDE
                - FOWNER
                - SETUID
                - SETGID
            mem_limit: 512m
            cpus: 1
            ports: ["3000:3000"]  # runs on 3000 internally
            env_file:
                - .env
            volumes:
                - "./data:/data"
                - "./queries-metadata:/queries-metadata"
            environment:
                - RACK_ENV=production
                - APP_ENV=production     # both for redundancy

### Start 

`docker-compose up -d` and look for errors...

### Testing

#### alive?
`curl -v -H "Authorization: Bearer YesItsMe" http://localhost:3000/severance`

if you see an error, there is a problem!  Check what kind of error, and make sure that the auth key is what you expect as set in the `.env` file


#### Any known queries?
`curl -X GET http://localhost:3000/severance/available_queries   -H "Authorization: Bearer YesItsMe"   -H "Accept: application/json"`

returns JSON annotation of known queries (documentation pending!)

#### Submit a query request

```
curl -v -X POST http://localhost:3000/severance/queries   -H "Content-Type: application/json"   -H "Authorization: Bearer YesItsMe"   -d '{
    "query_id": "count",
    "bindings": {
      "orphacode": "http://www.orpha.net/ORDO/Orphanet_730"
    }
  }'
```

*response:*

```
HTTP/1.1 201 Created
Location:  http://localhost:3000/severance/jobs/ABC123
...
...
```

#### Check submitted query status

`curl -X GET http://localhost:3000/severance/jobs/ABC123   -H "Authorization: Bearer YesItsMe"   -H "Accept: application/json"`

*response:*

```
...
HTTP/1.1 201 Created...
Location:  http://localhost:3000/severance/jobs/ABC123
retry-after: 10
...
{"status": "processing"}
```

##  NOW START INTERNAL

The internal component will immediately ask the External component if it has any queries.

Your query just submitted will be picked-up and answered (assuming that Internal is functional!)

#### Check submitted query status

`curl -X GET http://localhost:3000/severance/jobs/ABC123   -H "Authorization: Bearer YesItsMe"   -H "Accept: application/json"`

*response:*

```
HTTP/1.1 200 OK
Content-type:  text/csv
...
...
count
123
```


# API

## /severance/available_queries

Retrieves a JSON list of named queries that are available from the Internal component

**request**

`curl -X GET http://localhost:3000/severance/available_queries   -H "Authorization: Bearer YesItsMe"   -H "Accept: application/json"`


**response**
```
[
    "query_id": "count",
    "title": "Count matching patients",
    "summary": "Returns the number of patients in the registry with the corresponding disease code",
    "tags": [
      "Patient Count"
    ],
    "variables": [
      "orphacode"
    ],
    "variable_types": {
      "orphacode": "iri"
    },
    "examples": {
      "orphacode": "http://www.orpha.net/ORDO/Orphanet_730"
    },
    "endpoint_in_url": false
  }
]
```

This response shows the key components that you need to construct a query request:
1)  The query identifier
2)  The query variables
3)  What type of data is allowed for each variable
4)  An example (there's no guarantee that the example will result in a match - it is informative only!)

From this, a valid query binding would be(using the exemplar value):

```
{
    "query_id": "count",
    "bindings": {
      "orphacode": "http://www.orpha.net/ORDO/Orphanet_730"
    }
}
```
note that URLs are submitted as strings, without any "<...>"


## /severance/queries

POST a valid query binding to this endpoint to add it to the query queue.

Example:
```
curl -v -X POST http://localhost:3000/severance/queries   -H "Content-Type: application/json" \
  -H "Authorization: Bearer YesItsMe"   -d '{ \
    "query_id": "count", \
    "bindings": { \
      "orphacode": "http://www.orpha.net/ORDO/Orphanet_730" \
    } \
  }'

```

the Location header of the response tells you the addess you should poll to get your answer.  The frequency with which the query queue is accessed is entirely up to the service provider - minutes, days, or longer.  
