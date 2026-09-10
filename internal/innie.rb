#!/usr/bin/env ruby
# frozen_string_literal: true

require 'net/http'
require 'json'
require 'fileutils'
require_relative 'annotation_parser'

include QueryAnnotationParser

# Read once at boot from the same VERSION file the Dockerfile bakes in as an
# OCI label. Internal has no HTTP endpoint of its own to query this from at
# runtime (unlike External's GET /severance), so it's logged at startup
# instead -- the only way to confirm it from a running container otherwise.
SEVERANCE_VERSION = File.read(File.join(__dir__, 'VERSION')).strip
warn "Innie starting (v#{SEVERANCE_VERSION})"

# External service URL (e.g. the UI / orchestrator service)
EXTERNAL_URL = ENV.fetch('EXTERNAL_URL', 'http://localhost')

# Triplestore SPARQL endpoint URL
TRIPLESTORE_URL = ENV.fetch('TRIPLESTORE_URL', 'http://localhost')

# Directory containing the .rq query files (usually mounted read-only)
QUERY_DIR = ENV.fetch('QUERY_DIR', '')

# How often to poll the external service for new jobs (in seconds)
POLL_INTERVAL = ENV.fetch('POLL_INTERVAL', 10)&.to_i

# Output format for SPARQL results: 'json' (default) or 'csv'
result = ENV.fetch('RESULT_FORMAT', 'json').to_s.strip.downcase
RESULT_FORMAT = result == 'csv' ? 'csv' : 'json'

# Accept header sent to the triplestore
ACCEPT_HEADER = RESULT_FORMAT == 'csv' ? 'text/csv' : 'application/sparql-results+json'

# AES-256-GCM encryption key derived from hex environment variable
ENCRYPTION_KEY = [ENV.fetch('ENCRYPTION_KEY_HEX',
                            '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef')]&.pack('H*')

# ============== AES-256-GCM helpers ==============

# Encrypts data using AES-256-GCM.
#
# @param data [String] Plaintext data to encrypt
# @return [String] Encrypted binary data (nonce + tag + ciphertext)
# Note: This method aggressively attempts to zero out the plaintext data after
# encryption to minimize in-memory exposure.
# Warning: While this method tries to reduce the risk of sensitive data lingering in memory,
# it cannot guarantee complete security due to Ruby's memory management and string immutability.
# Use with caution and consider additional security measures if handling highly sensitive data.
def encrypt(data)
  # Work on a binary copy
  data = data.dup.force_encoding(Encoding::BINARY)

  cipher = OpenSSL::Cipher.new('aes-256-gcm')
  cipher.encrypt
  cipher.key = ENCRYPTION_KEY
  nonce = cipher.random_iv
  ciphertext = cipher.update(data) + cipher.final
  tag = cipher.auth_tag

  # Zero out our working copy before returning
  data.replace("\0" * data.bytesize)
  data.clear
  nonce + tag + ciphertext
end

# Decrypts data previously encrypted with {#encrypt}.
#
# @param encrypted [String] Binary encrypted data (nonce + tag + ciphertext)
# @return [String] Decrypted plaintext
# @raise [OpenSSL::Cipher::CipherError] if decryption fails (wrong key, tampered data, etc.)
def decrypt(encrypted)
  cipher = OpenSSL::Cipher.new('aes-256-gcm')
  cipher.decrypt
  cipher.key = ENCRYPTION_KEY
  nonce = encrypted[0, 12]
  tag = encrypted[12, 16]
  ct = encrypted[28..]
  cipher.iv = nonce
  cipher.auth_tag = tag
  cipher.update(ct) + cipher.final
end

# Encrypts `plaintext` and pushes it to External as job `uuid`'s result.
# Zeroes and releases our own working copy after encrypting (mirrors the
# hygiene already applied to real triplestore responses in the main loop
# -- see "SECURE RESULT HANDLING" below). Used both for real results and
# for the safe "no results" body pushed back when a job is rejected (see
# InvalidIriError / empty_result_body).
#
# @param uuid [String] Job UUID
# @param plaintext [String] Result body to encrypt and push
def push_result(uuid, plaintext)
  plaintext = plaintext.dup.force_encoding(Encoding::BINARY)
  encrypted_result = encrypt(plaintext)
  plaintext.replace("\0" * plaintext.bytesize)
  plaintext.clear
  GC.start(full_mark: true, immediate_sweep: true) if defined?(GC)

  push_uri = URI("#{EXTERNAL_URL}/severance/jobs/#{uuid}/result")
  http = Net::HTTP.new(push_uri.hostname, push_uri.port)
  http.use_ssl = (push_uri.scheme == 'https')

  push_req = Net::HTTP::Post.new(push_uri)
  push_req['Content-Type'] = 'application/octet-stream'
  push_req.body = encrypted_result

  http.request(push_req)
end

# A safe, zero-row result body shaped to match RESULT_FORMAT, pushed when
# a job is rejected before ever reaching the triplestore (see
# InvalidIriError) -- so a rejected job still resolves promptly for the
# caller instead of hanging until their own poll ceiling, without
# executing or echoing back anything attacker-controlled.
def empty_result_body
  if RESULT_FORMAT == 'csv'
    ''
  else
    JSON.generate({ 'head' => { 'vars' => [] }, 'results' => { 'bindings' => [] } })
  end
end

# ------------------------------------------------------------------
# Helper: Escape value for safe insertion into SPARQL
# ------------------------------------------------------------------

# Raised when a binding declared as `iri` contains a character that isn't
# legal inside a SPARQL IRIREF. Deliberately carries only the variable
# name, never the offending value -- see the note on InvalidIriError below.
class InvalidIriError < StandardError; end

# Raised when a binding value contains a byte sequence that isn't valid
# UTF-8. `JSON.parse` (used both by Outie writing the job file and here
# when nothing re-validates it) does not check encoding validity, so a
# tainted value can ride all the way from an attacker's request body into
# this method's own `.to_s.strip` call, which raises an uncaught
# ArgumentError/Encoding::CompatibilityError. Unlike External (a per-request
# web server that survives an unhandled exception in one request), Innie's
# main loop has no supervisor around this call other than the explicit
# `rescue InvalidIriError` -- an uncaught exception here kills the entire
# polling process, and neither compose file sets a `restart:` policy, so it
# stays dead until someone manually restarts the container. Rejecting the
# job the same way an invalid IRI is rejected (see below) closes that off.
class InvalidEncodingError < StandardError; end

# Characters forbidden inside a SPARQL IRIREF (SPARQL 1.1 grammar, §19.8):
#   '<' ([^<>"{}|^`\]-[#x00-#x20])* '>'
# i.e. an IRI's own content may not contain <, >, ", {, }, |, ^, backtick,
# backslash, or any control/whitespace character (0x00-0x20 inclusive).
INVALID_IRIREF_CHARS = /[\x00-\x20<>"{}|^`\\]/.freeze

# Whether `value` is safe to place, unescaped, between < and > in a SPARQL
# query. There is no valid *escaping* for a raw IRI the way there is for a
# quoted string literal -- per the grammar, a value either only contains
# legal IRIREF characters or it doesn't, so an invalid one must be
# rejected outright, not sanitized and passed through.
def valid_iriref?(value)
  !value.match?(INVALID_IRIREF_CHARS)
end

# Replaces grlc-style parameters (`?_name_type` or `?__name_type`) in a SPARQL query
# with properly escaped and typed values from the provided bindings.
#
# @param query [String] The original SPARQL query text
# @param bindings [Hash] Parameter values (key => value)
# @param variable_types [Hash] Optional type information from the annotation parser
#                              (used to decide whether to treat a value as IRI)
#
# @return [String] The query with all parameters substituted
# @raise [InvalidIriError] if an `iri`-typed binding contains a character
#   that isn't legal inside a SPARQL IRIREF -- see the security note above
#   InvalidIriError. Without this check, an attacker-controlled value for
#   any iri-typed variable in ANY installed query could break out of the
#   intended `<...>` and inject arbitrary additional SPARQL (a UNION, a
#   FILTER, a completely different graph pattern) -- turning a
#   pre-approved query into a vehicle for accessing data well outside
#   what its author intended, with no new query_id required at all.
def substitute_grlc_bindings(query, bindings, variable_types = {})
  return query if bindings.nil? || bindings.empty?

  bindings.each do |k, v|
    next if v.nil?

    if v.is_a?(String) && !v.valid_encoding?
      raise InvalidEncodingError, "Binding '#{k}' contains a byte sequence that is not valid UTF-8 (rejected, not substituted)"
    end

    warn "Processing binding: #{k} => #{v.inspect}"
    warn "Variable types for #{k}: #{variable_types[k.to_s]}"
    # Determine if this variable is declared as iri
    is_iri = variable_types[k.to_s]&.downcase == 'iri'
    warn "Variable '#{k}' is declared as IRI: #{is_iri}"
    escaped_value = if is_iri
                      stripped = v.to_s.strip
                      # Un-wrap a caller-supplied <...> so we validate the
                      # actual IRI content either way, not the brackets.
                      bare = stripped.start_with?('<') && stripped.end_with?('>') ? stripped[1..-2] : stripped
                      unless valid_iriref?(bare)
                        raise InvalidIriError, "Binding '#{k}' declared as iri contains a character " \
                                                'not permitted inside a SPARQL IRIREF (rejected, not substituted)'
                      end
                      "<#{bare}>"
                    else
                      escape_for_sparql(v)
                    end
    warn "Escaped value for #{k}: #{escaped_value}"

    # Match both ?_key_type and ?__key_type
    pattern = /(?:\?__|\?_)#{Regexp.escape(k.to_s)}_[\w:]+/i
    query.gsub!(pattern) do |_match|
      escaped_value
    end

    warn "→ Substituted ?_#{k}_* → #{escaped_value}"
  end
  query
end

# Escapes a Ruby value for safe use inside a SPARQL query string.
#
# @param value [Object] The value to escape (String, Numeric, Boolean, etc.)
# @return [String] A properly quoted and escaped SPARQL literal
def escape_for_sparql(value)
  case value
  when TrueClass, FalseClass then value.to_s
  when Numeric then value.to_s
  when String
    escaped = value.gsub('\\', '\\\\').gsub('"', '\\"')
    "\"#{escaped}\""
  else
    "\"#{value.to_s.gsub('\\', '\\\\').gsub('"', '\\"')}\""
  end
end

# Placeholder for future query validation logic.
#
# @param _query [String] The SPARQL query to validate
# @return [Boolean] Currently always returns true
def validate_query(_query)
  true # ← stub – replace with real validation later
end

def process_queries
  begin
    queries = QueryAnnotationParser::Parser.process_folder(QUERY_DIR)
  rescue StandardError
    warn "⚠ Failed to parse query annotations in #{QUERY_DIR}: #{$!.class} - #{$!.message}"
    return {}
  end

  all_queries = {}
  # Build the final list that Outie expects
  available_queries = queries.map do |metadata|
    # Compute smart bindings from defaults + enumerate
    bindings = metadata['defaults'].dup || {}

    # If there are enumerated values, add them as arrays (for UI dropdowns)
    (metadata['enumerate'] || {}).each do |key, values|
      bindings[key] = values if values.is_a?(Array) && !values.empty?
    end

    queryhash = {
      'query_id' => metadata['query_id'],
      'title' => metadata['title'],
      'summary' => metadata['summary'],
      'description' => metadata['description'],
      'tags' => metadata['tags'],
      'variables' => metadata['variables'],
      'variable_types' => metadata['variable_types'],
      'examples' => bindings,
      'pagination' => metadata['pagination'],
      'method' => metadata['method'],
      'endpoint' => metadata['endpoint'],
      'endpoint_in_url' => metadata['endpoint_in_url']
    }.compact # remove nil keys

    all_queries[metadata['query_id']] = queryhash # for quick lookup later when processing jobs
  end

  begin
    # ONE single POST with the full list of available queries
    push_uri = URI("#{EXTERNAL_URL}/severance/available_queries")
    warn "Pushing #{available_queries.size} available queries to #{push_uri.inspect}..."
    push_req = Net::HTTP::Post.new(push_uri)
    push_req['Content-Type'] = 'application/json; charset=utf-8'
    push_req.body = JSON.generate(available_queries)

    http = Net::HTTP.new(push_uri.hostname, push_uri.port)
    http.use_ssl = (push_uri.scheme == 'https')
    res = http.request(push_req)

    if res.is_a?(Net::HTTPSuccess)
      warn "✓ Registered #{available_queries.size} queries"
      available_queries.each do |q|
        warn " • #{q['query_id']} (#{q['title'] || 'no title'})"
      end
    else
      warn "⚠ Failed to register queries: #{res.code} #{res.message}"
    end

    warn "Registration completed for #{available_queries.size} queries"
  rescue StandardError => e
    warn "❌ Failed to push queries on startup: #{e.class} - #{e.message}"
  end
  all_queries
end

# ========================================================================
# ============================ MAIN LOOP =================================
# ========================================================================

# Main polling loop: continuously pull jobs from the external service,
# execute them against the triplestore, and push results back.
loop do
  # On startup: Push all query metadata to the external service (Outie)
  # so the UI can list available queries and later request them by ID.
  all_queries = process_queries

  begin
    poll_uri = URI("#{EXTERNAL_URL}/severance/queue/pull")
    warn "Polling for new jobs at #{poll_uri.inspect}..."
    http = Net::HTTP.new(poll_uri.hostname, poll_uri.port)
    http.use_ssl = (poll_uri.scheme == 'https')
    response = http.request(Net::HTTP::Get.new(poll_uri))
  rescue StandardError => e
    warn "⚠ Failed to poll for jobs: #{e.class} - #{e.message}"
    sleep POLL_INTERVAL
    next
  end
  unless response.is_a?(Net::HTTPSuccess)
    sleep POLL_INTERVAL
    next
  end
  unless response.body && !response.body.strip.empty?
    sleep POLL_INTERVAL
    next
  end

  job = JSON.parse(response.body)
  uuid = job['uuid']
  raise 'No UUID in job response!' unless uuid

  query_id = job['query_id']
  bindings = job['bindings'] || {}

  # `query_id` is attacker-influenced input (it rides in from a caller's
  # request all the way through Outie's queue). It is used below to build
  # `query_path` by plain string interpolation -- with no check here, a
  # value like `../demo-queries/count` would happily resolve outside
  # QUERY_DIR and let a caller execute a .rq file the deployer never
  # installed/vetted (Outie also now whitelists query_id's characters, but
  # this check does not rely on that -- Internal must not trust it either).
  # Requiring an exact match against `all_queries` (populated only from
  # files `process_queries` actually found by scanning QUERY_DIR itself)
  # closes this structurally: no key can exist there that wasn't a real,
  # already-installed query's own declared query_id.
  unless all_queries.key?(query_id)
    warn "Unknown or disallowed query_id: #{query_id.inspect}"
    sleep POLL_INTERVAL
    next
  end

  query_path = "#{QUERY_DIR}/#{query_id}.rq"
  unless File.exist?(query_path)
    warn "Query file missing: #{query_path}"
    sleep POLL_INTERVAL
    next
  end

  query = File.read(query_path, encoding: 'UTF-8')
  warn "Found query #{query_id} (#{query_path})"
  warn "all_queries #{all_queries.inspect}"

  # === Bind grlc-style placeholders (?_key_type) ===
  begin
    query = substitute_grlc_bindings(query, bindings, all_queries[query_id]['variable_types'])
  rescue InvalidIriError, InvalidEncodingError => e
    # Reject the job outright rather than executing anything -- see the
    # security note on InvalidIriError above. Pushes a safe, zero-row
    # result so the caller resolves promptly instead of hanging until
    # their own poll ceiling, without ever running the tainted query or
    # echoing back anything attacker-controlled.
    warn "⚠ Rejected job #{uuid} for query #{query_id}: #{e.message}"
    begin
      push_result(uuid, empty_result_body)
    rescue StandardError => push_error
      warn "⚠ Failed to push rejection result for job #{uuid}: #{push_error.class} - #{push_error.message}"
    end
    sleep POLL_INTERVAL
    next
  end
  warn "Final query after binding:\n#{query}"

  validate_query(query) # currently a no-op, but can be expanded with real validation logic later

  # === Execute against triplestore with authentication ===
  uri = URI(TRIPLESTORE_URL)
  warn "SPARQL endpoint: #{uri.inspect}"

  req = Net::HTTP::Post.new(uri)
  req['Accept'] = ACCEPT_HEADER
  req['Content-Type'] = 'application/sparql-query'
  req.body = query

  # Add Basic Authentication if credentials are provided
  if ENV['TRIPLESTORE_USER'] && ENV['TRIPLESTORE_PASS']
    req.basic_auth(ENV['TRIPLESTORE_USER'], ENV['TRIPLESTORE_PASS'])
    warn "Using Basic Auth for user: #{ENV['TRIPLESTORE_USER']}"
  else
    warn 'Warning: TRIPLESTORE_USER or TRIPLESTORE_PASS not set - running without authentication'
  end

  res = Net::HTTP.start(uri.hostname, uri.port, use_ssl: uri.scheme == 'https') do |http|
    http.request(req)
  end

  warn "SPARQL SERVER: HTTP result status: #{res.code}"

  # ====================== SECURE RESULT HANDLING ======================
  begin
    # 1. Immediately duplicate the body as BINARY
    plaintext = res.body.dup.force_encoding(Encoding::BINARY)
    # 2. Encrypt our copy immediately
    encrypted_result = encrypt(plaintext)

    # 3. Zero out the ORIGINAL response body inside Net::HTTPResponse
    if res.body
      res.body.replace("\0" * res.body.bytesize)   # overwrite with zeros
      res.body.clear                               # release buffer
    end
    # 4. Aggressively zero our working plaintext
    plaintext.replace("\0" * plaintext.bytesize)
    plaintext.clear
    plaintext = nil
  ensure
    # Final cleanup
    plaintext = nil
    # Optional: encourage Garbage Collection to reclaim the memory faster
    GC.start(full_mark: true, immediate_sweep: true) if defined?(GC)
  end
  # warn "Result size before encryption: #{result_body.bytesize} bytes"
  # warn "Encrypted size: #{encrypted_result.bytesize} bytes"

  # === Push encrypted result to external service ===
  begin
    push_uri = URI("#{EXTERNAL_URL}/severance/jobs/#{uuid}/result")
    http = Net::HTTP.new(push_uri.hostname, push_uri.port)
    http.use_ssl = (push_uri.scheme == 'https')

    push_req = Net::HTTP::Post.new(push_uri)
    push_req['Content-Type'] = 'application/octet-stream'   # ← changed for binary encrypted data
    push_req.body = encrypted_result                        # binary data, do NOT force_encoding to UTF-8

    push_res = http.request(push_req)
    warn "Job #{uuid} completed (push status: #{push_res.code})"
    puts "[#{Time.now}] Job #{uuid} for query #{query_id} finished"
    # Small delay before next poll
  rescue StandardError => e
    warn "⚠ Failed to push results for job #{uuid}: #{e.class} - #{e.message}"
  end
  sleep POLL_INTERVAL
end
