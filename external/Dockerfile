FROM ruby:3.2-slim

# Plain public image, not a "hardened" vendor variant -- real-world security
# scan comparisons (own patching pipeline: shell in, OS-level upgrade,
# recommit) showed better results from this than from Docker Hardened
# Images, so that's the deliberate choice here, not an oversight.

# Install build deps + gosu (for dropping privileges safely)
RUN apt-get update -qq && \
    apt-get install -y --no-install-recommends \
      build-essential \
      gosu \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user/group. UID is pinned to 1000 (matching
# internal/Dockerfile's own convention) because entrypoint.sh chowns the
# mounted volumes to ${UID:-1000}:${GID:-1000} before gosu drops privileges
# to this user -- without an explicit UID here, useradd auto-assigns one
# from the system range (999, confirmed live), leaving the app running as
# a different UID than the one its own entrypoint just chowned the volumes
# to, and unable to write to /data/queue or /data/results at all.
RUN groupadd -r -g 1000 severance && \
    useradd -r -u 1000 -g severance -d /app -s /sbin/nologin -c "Docker app user" severance

WORKDIR /app

# Gem caching layer
COPY Gemfile Gemfile.lock ./
RUN bundle install --jobs 4 --retry 3

# Copy app + entrypoint
COPY VERSION outie.rb ./
COPY entrypoint.sh .
RUN chmod +x entrypoint.sh

# Not just documentation -- outie.rb reads this same file at runtime and
# reports it from GET /severance, so the running version is queryable, not
# just visible on the image metadata.
ARG SEVERANCE_VERSION
LABEL org.opencontainers.image.title="severance-external" \
      org.opencontainers.image.version="${SEVERANCE_VERSION}" \
      org.opencontainers.image.description="Severance: secure SPARQL service (External component)"

# Pre-create dirs (optional, but good for non-volume cases)
RUN mkdir -p /data/queue /data/results

# VOLUME declaration (Docker knows this is a mount point)
VOLUME /data

ENV PORT=3000
EXPOSE 3000

# Start as root → entrypoint will chown then drop to severance
ENTRYPOINT ["./entrypoint.sh"]
