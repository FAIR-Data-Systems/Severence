<img src="../docs/SeverenceSMW.png"/>

# Severance: Secure SPARQL Service

# Installing the Internal Component

## Prerequisites

1. A Virtuoso instance up and running, containing...
2. Patient Registry data following the CARE-SM-2 model, loaded into a named graph (Virtuoso is one-instance-one-database, with no separate "repository" concept the way GraphDB has -- isolation between installs is via named graph, not a repository name)
3. A Virtuoso user with read (`SPARQL_SELECT`) access to that data -- see the note on `TRIPLESTORE_USER`/`TRIPLESTORE_PASS` below on why this must be a real Digest-authenticated user, not an anonymous read
4. An instance of Severence External running in your DMZ, and
5. It's API URL must be visible from THIS SERVER to reach-out

## Configuration

1. **Start with an empty folder**, and (as you, not as root) create a subfolder `./queries`
2. Make a copy of the env_template file to and edit it 
3. save it as `.env`
4. create a docker-compose.yml as instructed below 

### env_template

    # must be the same key as the External component!
    ENCRYPTION_KEY_HEX=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
    RESULT_FORMAT=csv  # must be the same as the External component!
    QUERY_DIR=/queries  # DO NOT CHANGE THIS unless you really know what you're doing
    EXTERNAL_URL=http://111.111.111.111:3000   # The URL to the External API.  
    TRIPLESTORE_URL=http://localhost:8890/sparql-auth  # Virtuoso's Digest-authenticated SPARQL endpoint
    TRIPLESTORE_USER = markw
    TRIPLESTORE_PASS = markw
    POLL_INTERVAL=10  # seconds
    UID=1000   #  at terminal:   id -u
    GID=1000   # at terminal:  id -g

The `ENCRYPTION_KEY_HEX` must be shared with the external componenet, since all results are encrypted

**A note on `TRIPLESTORE_URL`/`TRIPLESTORE_USER`/`TRIPLESTORE_PASS`:** Virtuoso's plain `/sparql` endpoint serves the anonymous `nobody` account, which -- unless a deployment has deliberately locked it down (see `Sextans-Suite`'s `virtuoso-initdb/lockdown-anonymous-sparql.sql` for the pattern Sextans Fix/Sight both apply) -- can read every graph in the store with no credentials at all. Internal therefore talks to `/sparql-auth` by default whenever `TRIPLESTORE_USER`/`TRIPLESTORE_PASS` are set, using real HTTP Digest authentication (Virtuoso rejects Basic auth outright on its authenticated endpoints, 401 with no retry). If you leave the credentials unset, Internal falls back to an unauthenticated request against whatever URL you give it -- only appropriate for a triplestore/deployment that doesn't require auth for reads at all.

write this to `.env` after editing.  UID and GID ensure that you have access to modify the `./queries` folder.

Test your access to the external URL by calling, e.g. `http://111.111.111.111:3000/severance`  You will either get a message or an "Unauthorized" response.  Any other kind of error means you cannot see the server from here.

### docker-compose.yml

For security, this container runs with the permissions of the user who you declare in the .env as the user who will be starting this container.

NEVER START IT AS ROOT!!  YOU HAVE BEEN WARNED!

UID AND GID MUST BE CORRECT!  See instructions in the env_template and below for how to know that
**You must get the permissions correct, or the container will not run properly, if at all.**  

Take a moment and figure out your UID and GID!  It defaults to 1000/1000, which is the first non-root user that is created on a system... but that is just a very bad guess.  Take a moment and get it right!

Internal must be able to "see" the External component and the triplestore, just as you
did when you tested access in the last step -- but it doesn't need `network mode: host`
to do that, since Internal never listens on a port of its own; it only ever makes
outbound requests.

**The normal case -- Internal and External on separate servers (the expected,
"Severed" deployment topology):** ordinary Docker bridge networking already reaches
any real IP address or domain name on your LAN or the internet with no special
configuration at all -- this is standard outbound NAT'd connectivity, unrelated to
`network_mode: host`. Just set `EXTERNAL_URL`/`TRIPLESTORE_URL` to the real address
of those servers (verified live: a plain bridge-networked container reaches both a
real internet domain name and another host's IP directly, no extra config needed).

**The one case that does need something extra -- testing with Internal and External
on the *same* machine:** `localhost` inside a container means the container itself,
not the host, so if you're running everything on one box for testing, point
`EXTERNAL_URL`/`TRIPLESTORE_URL` at `host.docker.internal` instead of `localhost` --
the `extra_hosts` entry below makes that resolve to the host.

    services:
    internal:
        restart: always
        security_opt:
          - "no-new-privileges:true"
        cap_drop:
          - ALL
        mem_limit: 512m
        cpus: 1
        extra_hosts:
          - "host.docker.internal:host-gateway"   # a localhost-equivalent for same-host testing
        image: XXXXX  (the docker-compose in the example, it points to the latest patch)        env_file: .env
        volumes:
        - "./queries:/queries"
        tmpfs:
        - /tmp:size=64m,noexec,nosuid,nodev
        environment:
        - TMPDIR=/tmp
        - UID=${UID:-1000}   #the output of  id -u at the terminal, set in .env
        - GID=${GID:-1000}   #the output of  id -g at the terminal, set in .env
        user: "${UID:-1000}:${GID:-1000}"   # Run container as your host user, or 1000 fallback (which is usually the first non-root user created on a Linux system)  
        


### Start 

**You should not start Internal until you have installed and tested External**.  You will need to do some testing on External that will be interrupted by the polling from Internal.

`docker-compose up -d`


## QUERIES

In the `./queries` folder there are some examples of annotated queries that can be interpreted by Severance Internal.  If you modify these, your changes will be preserved from one compose-down/up to another.  If you need to fully reset, delete the content of the `./queries` folder and it will be re-populated with the example queries the next time you start.

We provide some [guidance for how to author these queries](./queries/README.md) so that they can be interpreted by Severance and used to build a sensible UI on the External side, and also to help them be more universally discoverable based on their Query Type.

**Note:**  The ./queries folder content is re-read every time Internal polls External, so you can dynamically change the queries in that folder and it will update on the next polling cycle.

### Optional: queries for the Beacon v2 facade

If you're running the optional Beacon facade (see the commented-out
`beacon` service in `external/docker-compose.yml`), copy
`implementation/Beacon2/severance-queries/individuals_exists.rq` and
`individuals_count.rq` (from the CARE-Semantic-Model-Version-2 repo) into
this `./queries` folder. Those two named queries are the entire dependency
the facade has on Internal -- without them, its `/individuals` endpoint
will submit jobs Internal can't find (`Query file missing` in Internal's
logs) and every request will eventually time out waiting for a result.
See that file's own README for the filter contract and the modeling
assumptions baked into it.


