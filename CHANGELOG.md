# Changelog

All notable changes to this project are documented here. Format loosely follows [Keep a Changelog](https://keepachangelog.com/).

## [Unreleased]

### Changed

- `ALLOWED_INTERNAL_IPS` entries may now be a CIDR range (e.g. `192.168.1.0/24`) in addition to a bare IP or the `localhost` keyword. A malformed entry is skipped (logged) rather than rejecting every request. Closes #5.

- `Security/security-patch.sh` rebuilds both images from source, applies an OS-level `apt` update/dist-upgrade, scans with Trivy, pushes, and regenerates `external/docker-compose.yml`/`internal/docker-compose.yml` from new `Security/*-docker-compose-template-template.yml` masters -- keeping those two live compose files in sync with any hardening changes made here. `Security/parse-security-scans.rb` and `Security/build_register.py` (adapted for this repo's two images) turn scan output into `Security/vulnerability-register.csv`.
- Both Dockerfiles now remove the stale `net-imap` default gem after `bundle install`; both Gemfiles pin `net-imap`/`rack-session` to current patch versions.
- Removed the optional Beacon v2 facade section from `external/docker-compose.yml` and its references elsewhere in the docs.
- `query_id` (on `POST /severance/queries`) must now match a fixed, slash-free character whitelist before a job is queued (`external/outie.rb`); `internal/innie.rb` independently requires `query_id` to exactly match an entry in its own scanned query registry before doing any file lookup.
- Request bodies to `external/outie.rb`'s JSON endpoints, and binding values processed by `internal/innie.rb`, are now validated as well-formed UTF-8 before use (`external/outie.rb`'s `read_utf8_body!`; `internal/innie.rb`'s `substitute_grlc_bindings`, alongside its existing IRI validation).
- `external/outie.rb`'s failed-authentication log line no longer includes the Authorization header value or the configured `AUTH_TOKEN` -- it logs only whether the header was present, plus the caller's IP.
- **`internal/innie.rb` now connects to Virtuoso instead of GraphDB.** Added an `execute_sparql_query` helper that performs HTTP Digest authentication (via the `net-http-digest_auth` gem) against a `/sparql-auth`-style endpoint using a form-encoded `query=` body, when `TRIPLESTORE_USER`/`TRIPLESTORE_PASS` are configured; falls back to a plain unauthenticated request otherwise.
  - `TRIPLESTORE_URL`'s documented convention, `internal/env_template`, `internal/.env`, and `internal/README.md`'s prerequisites are updated accordingly (`http://host:8890/sparql-auth`).
  - Verified live end-to-end against a Virtuoso instance.
  - Uses `URI.encode_www_form_component` (from the `uri` stdlib, already loaded transitively) for the form-encoded query body rather than pulling in the `cgi` library for one method call.
  - Triplestore responses are now checked for success before being processed and encrypted; a failure to reach the triplestore at all is now handled the same way External's own polling failures already were, instead of stopping Internal.
- Both `external/outie.rb` and `internal/innie.rb` now require `ENCRYPTION_KEY_HEX` to be set to a value other than the documented example before starting.
- `external/docker-compose.yml` and `internal/docker-compose.yml`: added `restart: always`, `security_opt: no-new-privileges`, `cap_drop: [ALL]` (with a minimal `cap_add` on External for its existing chown-then-drop-privileges startup step), and resource limits.
- `internal/docker-compose.yml` no longer uses `network_mode: host` -- Internal never listens on a port, so ordinary bridge networking reaches External/the triplestore on a separate server exactly as before; `extra_hosts: [host.docker.internal:host-gateway]` is added for the same-host testing case, documented in `internal/README.md`.
- `external/Dockerfile`: the `severance` user's UID is now pinned to 1000, matching `internal/Dockerfile`'s existing convention and `entrypoint.sh`'s own volume-ownership step.
- `external/outie.rb`: Rack's default Host-header check is now disabled directly rather than through Sinatra's `set :protection, except:` option.

**Note:** `internal/sample_queries/count.rq` and `patient_filter.rq` are still written against CARE-SM v1's shape; they have not yet been checked against CARE-SM-2 data and will be updated in a follow-up commit.

### Security

- **Fixed a SPARQL injection vulnerability in `internal/innie.rb`'s binding substitution.** Any variable declared `iri` in a query's GRLC annotation (e.g. `?_disease_iri`) was wrapped in `<...>` with no validation of its contents. Since a SPARQL `IRIREF` has no escaping mechanism of its own (unlike a quoted string literal), a caller-supplied value containing a literal `>` could close the angle bracket early and inject arbitrary additional SPARQL — an extra `UNION`, `FILTER`, or graph pattern — directly into an otherwise pre-approved, named query. This defeated "queries are named and pre-approved, not arbitrary" as a security boundary: no new `query_id` was needed, only one existing `iri`-typed variable in any installed query, to read data well outside what that query's author intended (bounded only by whatever the Internal triplestore's own read-only credential can see, i.e. typically the whole repository).
  - Fixed by validating every `iri`-typed binding against the SPARQL 1.1 `IRIREF` grammar's disallowed character set (`< > " { } | ^` \` `\`, and control/whitespace characters) before substitution, and rejecting the job outright — with a safe, zero-row result pushed back so the caller resolves promptly rather than hanging — if it fails. There is no safe way to escape an invalid IRI value the way a string literal can be escaped; an invalid one must be refused, not sanitized and passed through.
  - The rejection path never executes the tainted query and never echoes the offending value back to the caller or into logs (only the variable name is logged), to avoid handing an attacker a probing oracle or a secondary log-injection surface.
  - Found while designing a Beacon v2 facade for CARE-SM-2
    (`CARE-Semantic-Model-Version-2` repo,
    `implementation/Beacon2/`) that itself relies on several `iri`-typed
    bindings (`sex`, `disease`, `symptom`) — the facade passes filter
    values through with no sanitization of its own, so it depended
    entirely on Severance's own escaping being correct. It wasn't; this
    fix closes that gap at the layer that actually needs to own it
    (Internal, where the query text and substitution logic live), rather
    than pushing validation out to every client integration individually.

### Added

- `CHANGELOG.md` (this file).
- `AUTH_TOKEN`'s real security properties (static bearer secret, replayable if ever exposed, blast radius bounded by the named-query design rather than the token itself) now documented explicitly in the top-level `README.md`'s "Possible Attacks?" list, `external/README.md`, and as a comment on the `AUTH_TOKEN` line in `external/env_template`.
