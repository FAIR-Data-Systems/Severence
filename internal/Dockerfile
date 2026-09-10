FROM ruby:3.2-slim

# Plain public image, not a "hardened" vendor variant -- real-world security
# scan comparisons (own patching pipeline: shell in, OS-level upgrade,
# recommit) showed better results from this than from Docker Hardened
# Images, so that's the deliberate choice here, not an oversight.

# Install only build dependencies
RUN apt-get update -qq && \
    apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# === Gem caching layer ===
COPY Gemfile Gemfile.lock ./
RUN bundle install --jobs 4 --retry 3

# net-imap ships as a Ruby "default gem" baked into the base image at
# whatever version that Ruby patch release bundled (0.3.9 here) -- pinning
# a newer version in the Gemfile (unused by this app; pulled in purely to
# get a patched version) installs it alongside the old one rather than
# replacing it, since Bundler and RubyGems' own default-gem installation
# use different paths. The stale, vulnerable default copy still sits on
# disk either way; remove it explicitly so it isn't there at all, rather
# than just shadowed by the newer bundled copy at runtime.
RUN gem uninstall -i /usr/local/lib/ruby/gems/3.2.0 net-imap --all --force || true

# Copy application code
COPY . .

# Not just documentation -- innie.rb reads this same file (copied in via
# `COPY . .` above) at startup and logs it, so the running version is
# confirmable in container logs, not just on the image metadata.
ARG SEVERANCE_VERSION
LABEL org.opencontainers.image.title="severance-internal" \
      org.opencontainers.image.version="${SEVERANCE_VERSION}" \
      org.opencontainers.image.description="Severance: secure SPARQL service (Internal component)"

# Copy demo queries to a protected location (never mounted)
COPY sample_queries /demo-queries

# Copy entrypoint and fix line endings
COPY entrypoint.sh /entrypoint.sh

# Create the queries directory in the image with correct permissions
# (helps on first run, though the entrypoint will override)
RUN mkdir -p /queries && \
    chown -R "${UID:-1000}:${GID:-1000}" /queries 2>/dev/null || true

RUN sed -i 's/\r$//' /entrypoint.sh && \
    chmod +x /entrypoint.sh

# We will set the actual UID/GID at runtime via docker-compose (see below)
# For now, create a placeholder user
RUN groupadd -r severance && \
    useradd -r -u 1000 -g severance -d /app -s /sbin/nologin severance

ENTRYPOINT ["/entrypoint.sh"]