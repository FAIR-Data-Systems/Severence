<img src="./docs/SeverenceSMW.png"/>

# Severance: Secure SPARQL Service

A highly secure, very lightweight, query system

**Version: see [`VERSION`](VERSION)** (currently `1.0.0`). `external/VERSION` and `internal/VERSION` are copies kept in sync for each component's own Docker build context -- bump all three together when releasing. Both `external/Dockerfile` and `internal/Dockerfile` bake this in as an `org.opencontainers.image.version` label via a `SEVERANCE_VERSION` build arg, e.g.:

    docker build --build-arg SEVERANCE_VERSION="$(cat VERSION)" -t sevexternal:$(cat VERSION) external/
    docker build --build-arg SEVERANCE_VERSION="$(cat VERSION)" -t sevinternal:$(cat VERSION) internal/

The running services also report it themselves: External's `GET /severance` includes it in its plain-text response, and Internal logs it once at startup (it has no HTTP endpoint of its own to query it from).

The name comes from the popular TV series [Severance](en.wikipedia.org/wiki/Severance_(TV_series)) where there is no communication between someone's "public facing self", and their "work self".  The transition happens while riding the elevator to their office (the project logo). The outside world is completely excluded from the internal, very sensitive business.

##  Install instructions (do things in this order!)

* [Installing External](./external/README.md)
* [Installing Internal](./internal/README.md)


## Severed for Security: Users are Outside, Queries stay Inside

**Query Flow Diagram**

<img src="./docs/Severence%20Functionality.png"/>

**Interoperability and Security Features:**
1. Requires an authorization token (from whatever mechanism you wish)
2. Queries are named and pre-approved, not arbitrary;
3. The query itself is never passed.  It exists only in the internal component. refered-to by name
4. Follows Web standards for queued processes
5. External and Internal components are fully independent (containers); internal can be switched off and external will continue to queue (no lost requests)
6. No external connection to the secure area→ Inside to Outside only
7. Impossible to DoS the Internal component - queue is accessed one-query-at-a-time
8. Data in the “intermediate store” is immediately encrypted upon arrival from the Triplestore
10. Data is decrypted and deleted as soon as it is called by the user - no second chances, but also lower risk
11. Unencrypted data never touches the disk; unencrypted data, on both internal and external sides, is only ever held in-memory.
12. Variables containing unencrypted data, and the web server cache, are "zero'd out" and cleared from memory immediately after data is encrypted, minimizing the time unencyrpted data is stored in memory.
13. The Internal component runs with a RAM-based tempfile system, such that attempts to write to /tmp do not go to disk
14. Code content of the Docker Containers is minimal - very low profile for security risks.
15. Containers both run as unprivileged users
16. Incoming query bindings are cleansed before being placed into a query, not merely quoted: `iri`-typed bindings are validated against the SPARQL 1.1 `IRIREF` grammar's disallowed characters and rejected outright (not sanitized and passed through) if invalid, and other typed bindings are quote-escaped. This closes off using a pre-approved query's own parameters as an injection vector to reach data outside that query's intended scope -- see CHANGELOG.md for the vulnerability this fixed.

**A note on how this list and the one below are produced:** several of the items above and attack scenarios below (including the injection fix referenced in #16) were identified through simulated/predicted attack analysis performed with Claude AI, not from a professional penetration test or formal security audit. This is a useful additional lens, but it is not a substitute for one, and there is no guarantee it has found every vulnerability. Treat this list as "known issues considered and addressed so far," not as "a certified list of everything that could go wrong."

**Possible Attacks?**
1. Modify queries - high impatct attack.  Likelihood?  Attacker needs to either a) secretly change the query in the GitHub so that a corrupted query is pulled by the Inside.  b) the Inside needs to forget to vet the queries they author or pull from GitHub (since this is voluntary and manual!) or c) the attacker is already inside the protected space and has file-level access to modify the query - in that case, there are bigger problems!  Most likely attacker profile for all of these is a rogue employee
2. Modification of Docker Image - high-impact attack.  Similar risk profile as above.
3. All other attacks we can imagine already require the attacker to be inside of the Secure Zone, which is already at the highest level of impact regardless of this software security.
4. **`AUTH_TOKEN` capture/replay - real, and worth understanding rather than assuming away.**  `AUTH_TOKEN` is a static, unsigned bearer value: whoever configures a client (a browser app, RedCap, a custom facade, etc.) to send it must keep it secret, but nothing in the protocol itself binds it to a specific request, a specific time window, or a specific caller.  Anyone who ever sees the value - a leaked config file, a compromised client host, a value visible in a client's own browser devtools/Network tab if it's ever handled client-side - can replay it indefinitely from anywhere.  **This is bounded, not eliminated, by the named-query design**: a stolen token only ever grants "submit one of the pre-approved `query_id`s with attacker-chosen binding values" - never arbitrary SPARQL, never discovery of the query text itself (which never leaves Internal).  Don't rely on `AUTH_TOKEN` as strong evidence of *who* is calling, only as a basic filter against casual/accidental access; if a specific integration needs real per-caller distinction, that has to be built into the query design (bindings, tighter per-query allow-lists) rather than assumed from the token.
