#!/usr/bin/env ruby
# frozen_string_literal: true

require 'sinatra'
require 'json'
require 'securerandom'
require 'openssl'
require 'fileutils'

# Sinatra 4.x/rack-protection 4.x enable Rack::Protection::HostAuthorization
# by default, which rejects any Host header outside a small built-in
# allowlist (`localhost`, IP literals, etc.) with a bare 403 "Host not
# permitted" -- before any application code, including the `before` filter
# below, ever runs. `set :protection, except: :host_authorization` (the line
# this replaced) is Sinatra's documented way to disable one protection, but
# has proven unreliable across versions in this codebase's sibling projects
# (see Sextans-Suite's yarrrml-rml/t.rb and Daemon/transform-cdev2.rb, which
# hit the identical failure and document it in more detail) -- confirmed
# live here too: External still rejected requests addressed by any hostname
# other than `localhost`/an IP literal (e.g. `host.docker.internal`, or any
# real DNS name a deployment might put in EXTERNAL_URL) even with this
# setting in place. Monkeypatching `accepts?` directly is the fix that has
# actually held. HostAuthorization exists to defend against DNS-rebinding
# attacks, where a *browser* is tricked into sending a request with an
# attacker-chosen Host header; External doesn't render browser-served HTML
# or trust the Host header for anything security-sensitive (every mutating
# endpoint already requires its own Bearer token), so disabling this
# specific check costs nothing real here.
require 'rack/protection/host_authorization'
class Rack::Protection::HostAuthorization
  def accepts?(_request)
    true
  end
end

configure do
  set :server, 'puma'
  set :bind, '0.0.0.0'
  set :port, ENV.fetch('PORT', 4567).to_i
  # Let `error` blocks (see JSON::ParserError below) handle exceptions
  # regardless of RACK_ENV -- Sinatra's development-mode exception page
  # would otherwise intercept them before a custom handler ever runs.
  set :show_exceptions, :after_handler
end

# Read once at boot from the same VERSION file the Dockerfile bakes in as an
# OCI label -- so the running service's version is queryable via GET
# /severance, not just visible on the image metadata.
SEVERANCE_VERSION = File.read(File.join(__dir__, 'VERSION')).strip

# Directory where pending and processing jobs are stored
QUEUE_DIR = ENV.fetch('QUEUE_DIR', '/data/queue')

# Directory where encrypted query results are stored
RESULTS_DIR = ENV.fetch('RESULTS_DIR', '/data/results')

# Debug - print ALL important variables
warn '=== Environment Debug ==='
warn "QUEUE_DIR = #{QUEUE_DIR.inspect}"
warn "RESULTS_DIR = #{RESULTS_DIR.inspect}"
warn "ENCRYPTION_KEY_HEX present = #{ENV['ENCRYPTION_KEY_HEX'] ? 'YES' : 'NO'}"
warn "AUTH_TOKEN = #{ENV['AUTH_TOKEN'] ? '*** (present)' : 'NOT SET'}"
warn "RESULT_FORMAT = #{ENV['RESULT_FORMAT'].inspect}"
warn '========================='

# Rack body wrapper that zeros out sensitive plaintext after the response
# has been fully flushed to the socket. Rack guarantees close is called
# after the last byte is written, so zeroing here is safe.
class ZeroingBody
  def initialize(data)
    @data = data
  end

  def each
    yield @data
  end

  def close
    return unless @data
    @data.replace("\0" * @data.bytesize)
    @data.clear
    @data = nil
    GC.start(full_mark: true, immediate_sweep: true) if defined?(GC)
  end
end

# AES-256-GCM encryption key derived from hex environment variable.
#
# Previously fell back to a fixed, literal default (published in this
# repo's own env_template/README as the example value) whenever
# ENCRYPTION_KEY_HEX wasn't set -- silently "encrypting" every result with
# a key anyone can read in this project's own source, giving a deployer who
# forgot to set it a false sense of security rather than an obvious error.
# Refusing to start is the fail-closed behavior this project uses
# everywhere else for exactly this class of mistake (see the IRI/encoding
# rejection paths in internal/innie.rb).
EXAMPLE_ENCRYPTION_KEY_HEX = '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef'
raw_encryption_key_hex = ENV['ENCRYPTION_KEY_HEX']&.strip
if raw_encryption_key_hex.nil? || raw_encryption_key_hex.empty?
  abort 'FATAL: ENCRYPTION_KEY_HEX is not set. Generate one with `openssl rand -hex 32` ' \
        'and set it identically on both External and Internal -- refusing to start with no key ' \
        'rather than silently falling back to a known, public default.'
elsif raw_encryption_key_hex == EXAMPLE_ENCRYPTION_KEY_HEX
  abort 'FATAL: ENCRYPTION_KEY_HEX is still the example value from env_template/README.md. ' \
        'Generate a real one with `openssl rand -hex 32` -- refusing to start with a key ' \
        'anyone can read in this project\'s own source.'
end
ENCRYPTION_KEY = [raw_encryption_key_hex].pack('H*')

# Content-Type for query results (json or csv)
CONTENT_TYPE = ENV['RESULT_FORMAT'] == 'csv' ? 'text/csv' : 'application/sparql-results+json'

# Create required directories on startup
begin
  FileUtils.mkdir_p([QUEUE_DIR, RESULTS_DIR])
  warn "✓ Successfully created directories: #{QUEUE_DIR} and #{RESULTS_DIR}"
rescue Errno::EACCES => e
  warn "❌ Permission error creating directories: #{e.message}"
  warn ' Make sure the volume is mounted and the user has write access.'
  raise
end

# ============== AES-256-GCM helpers ==============

# Encrypts data using AES-256-GCM.
#
# @param data [String] Plaintext data to encrypt
# @return [String] Encrypted binary data (nonce + tag + ciphertext)
def encrypt(data)
  cipher = OpenSSL::Cipher.new('aes-256-gcm')
  cipher.encrypt
  cipher.key = ENCRYPTION_KEY
  nonce = cipher.random_iv
  ciphertext = cipher.update(data) + cipher.final
  tag = cipher.auth_tag
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

# Raised when a request body claims to be JSON but contains a byte sequence
# that isn't valid UTF-8. `JSON.parse` itself does not reject this -- it
# happily returns a String tagged UTF-8 whose bytes are invalid, which then
# blows up with an uncaught ArgumentError/Encoding::CompatibilityError the
# moment any ordinary string method (`.strip`, string interpolation, etc.)
# touches it later in the request. Caught in the same place, and treated the
# same way, as a `JSON::ParserError` (see the `error JSON::ParserError`
# handler below) -- from an API consumer's perspective a body that isn't
# valid UTF-8 is just as malformed as one that isn't valid JSON syntax.
class InvalidBodyEncodingError < StandardError; end

# Reads and returns `request.body`, raising InvalidBodyEncodingError if it
# is not valid UTF-8. Call this before JSON.parse-ing a request body so the
# malformed-encoding case is rejected up front, not discovered later by
# whichever string method happens to touch the bad bytes first.
def read_utf8_body!
  raw = request.body.read
  raise InvalidBodyEncodingError unless raw.dup.force_encoding(Encoding::UTF_8).valid_encoding?

  raw
end

# ============== Security: Internal IP filtering for sensitive endpoints ==============

# Security filter applied to every request.
#
# - Internal endpoints (`/severance/queue/pull`, `/severance/jobs/*`, `/severance/available_queries`)
#   are only accessible from whitelisted IPs (default: localhost).
# - All other (user-facing) endpoints require a valid `Bearer` token if `AUTH_TOKEN` is set.
before do
  # === Internal calls from Innie (no auth required) ===
  internal_paths = ['/severance/queue/pull', '/severance/jobs/', '/severance/available_queries']
  if internal_paths.any? { |p| request.path_info.start_with?(p) }
    allowed_ips = (ENV['ALLOWED_INTERNAL_IPS'] || '127.0.0.1,::1,localhost').split(',').map(&:strip)
    client_ip = request.ip
    # Allow if client IP is in the list or it's localhost
    is_allowed = allowed_ips.include?(client_ip) ||
                 (allowed_ips.include?('localhost') && ['127.0.0.1', '::1'].include?(client_ip))
    halt 403, "Access denied from #{client_ip} - internal IP required" unless is_allowed
    # Internal call → bypass Bearer token check
    return
  end

  # === External/user-facing calls - require Bearer token ===
  if ENV['AUTH_TOKEN']
    auth_header = request.env['HTTP_AUTHORIZATION']
    expected = "Bearer #{ENV['AUTH_TOKEN']}"
    unless auth_header && auth_header.casecmp?(expected)
      # Never log the real AUTH_TOKEN (`expected`) or the caller-supplied
      # header -- the latter could itself be a leaked/guessed valid token
      # from elsewhere, and logging either one turns every failed auth
      # attempt into a cleartext secret sitting in container logs, readable
      # by anyone with `docker logs` access (a much wider audience than
      # anyone who should know the token). Presence/absence and the
      # caller's IP are enough to operate on without that exposure.
      state = auth_header ? 'present but did not match' : 'missing'
      warn "Auth failed from #{request.ip}: Authorization header #{state}"
      halt 401, 'Unauthorized'
    end
  end
end

# Submits a new query job for asynchronous execution.
#
# Accepts either JSON body or form parameters.
#
# @return [201] with `Location` header pointing to the job status
# @return [400] if `query_id` is missing or empty
post '/severance/queries' do
  # Safely parse input whether it's JSON or form data
  data = if request.content_type&.include?('application/json')
           JSON.parse(read_utf8_body!)
         else
           # For form-encoded or query params
           { 'query_id' => params['query_id'], 'bindings' => params.except('query_id') }
         end

  # Ensure we have a hash and extract query_id safely
  query_id = data.is_a?(Hash) ? data['query_id'] : nil
  halt 400, { error: 'query_id is required' }.to_json if query_id.nil? || query_id.to_s.strip.empty?

  # query_id ends up as a bare filename component on Internal's side
  # (`#{QUERY_DIR}/#{query_id}.rq` in innie.rb) with no further sanitization
  # there. Without this whitelist a caller could set query_id to something
  # like `../demo-queries/count` and make Internal read and execute a .rq
  # file the deployer never installed/vetted in their own QUERY_DIR --
  # defeating "queries are named and pre-approved, not arbitrary" entirely.
  # Same flat, slash-free convention used for this exact purpose elsewhere
  # in this project family (yarrrml-rml's `t.rb` type whitelist).
  unless query_id.to_s.strip.match?(/\A[a-zA-Z0-9_-]+\z/)
    halt 400, { error: 'query_id contains invalid characters' }.to_json
  end

  uuid = SecureRandom.uuid
  job = {
    'query_id' => query_id.to_s.strip,
    'bindings' => (data.is_a?(Hash) ? data['bindings'] || {} : {}),
    'submitted_at' => Time.now.to_i
  }

  File.write("#{QUEUE_DIR}/#{uuid}.pending.json", JSON.generate(job))

  status 201
  headers 'Location' => "#{request.base_url}/severance/jobs/#{uuid}"
  body ''
end

# ============== Catalog: Receive and serve list of available queries ==============

# Receives the full list of available queries from Innie and saves it to disk.
#
# @return [200] on success with count
# @return [400] if JSON is invalid
# @return [500] on other errors
post '/severance/available_queries' do
  queries = JSON.parse(read_utf8_body!)
  metadata_dir = ENV.fetch('METADATA_DIR', '/queries-metadata')
  warn "Metadata directory for available queries: #{metadata_dir}"
  active_queries_path = "#{metadata_dir}/active_queries.json"
  begin
    warn 'I Am', `whoami`
    File.write(active_queries_path, JSON.pretty_generate(queries))
  rescue Errno::EACCES => e
    warn "❌ Permission error writing available queries: #{e.message}"
    halt 500, { error: 'Permission denied writing available queries' }.to_json
  end
  warn "✓ Received and saved #{queries.size} available queries to #{active_queries_path}"

  status 200
  content_type 'application/json'
  body({ success: true, count: queries.size }.to_json)
rescue JSON::ParserError, InvalidBodyEncodingError => e
  warn "❌ Invalid JSON in /available_queries: #{e.message}"
  status 400
  content_type 'application/json'
  body({ error: 'Invalid JSON' }.to_json)
rescue StandardError => e
  warn "❌ Error saving available queries: #{e.message}"
  status 500
  content_type 'application/json'
  body({ error: 'Internal server error' }.to_json)
end

# Returns the current list of available queries (previously pushed by Innie).
get '/severance/available_queries' do
  metadata_dir = ENV.fetch('METADATA_DIR', '/queries-metadata')
  active_queries_path = "#{metadata_dir}/active_queries.json"

  if File.exist?(active_queries_path)
    content_type 'application/json'
    File.read(active_queries_path)
  else
    status 404
    content_type 'application/json'
    body({ error: 'No queries available yet' }.to_json)
  end
end

# ============== Status / Result retrieval ==============

# Returns the status or result of a job.
#
# @param uuid [String] Job UUID
# @return [202] if still processing
# @return [200] with result (and deletes files) if completed
# @return [404] if job not found
get '/severance/jobs/:uuid' do |uuid|
  pending     = "#{QUEUE_DIR}/#{uuid}.pending.json"
  processing  = "#{QUEUE_DIR}/#{uuid}.processing.json"
  result_file = "#{RESULTS_DIR}/#{uuid}.enc"

  if File.exist?(pending) || File.exist?(processing)
    status 202
    headers 'Retry-After' => '10'
    body '{"status":"processing"}'

  elsif File.exist?(result_file)
    plaintext = nil

    begin
      encrypted = File.binread(result_file)

      # Decrypt
      plaintext = decrypt(encrypted)

      # Hand plaintext to ZeroingBody, which yields it to Puma then zeros
      # it in close — called by Rack after the last byte hits the socket.
      content_type CONTENT_TYPE
      body ZeroingBody.new(plaintext)
      plaintext = nil # ZeroingBody is now sole owner

      # Clean up files
      File.delete(result_file) if File.exist?(result_file)
      File.delete(processing) if File.exist?(processing)
    rescue OpenSSL::Cipher::CipherError => e
      warn "[ERROR] Decryption failed for #{uuid}: #{e.message}"
      status 500
      body 'Decryption error'
    rescue StandardError => e
      warn "[ERROR] Serving result #{uuid}: #{e.message}"
      status 500
      body 'Server error'
    ensure
      # Safety net: zero plaintext if an exception fired before ZeroingBody took ownership
      if plaintext
        plaintext.replace("\0" * plaintext.bytesize)
        plaintext.clear
        plaintext = nil
        GC.start(full_mark: true, immediate_sweep: true) if defined?(GC)
      end
    end

  else
    status 404
    body '{"error":"not found"}'
  end
end

# ============== Internal: Push result from "Innie" ==============

# Receives the execution result from Innie and stores it encrypted.
#
# @param uuid [String] Job UUID
post '/severance/jobs/:uuid/result' do |uuid|
  # Read the incoming encrypted payload as raw binary
  encrypted_data = request.body.read.force_encoding(Encoding::BINARY)
  if encrypted_data.empty? || encrypted_data.bytesize < 28 # minimum size for AES-GCM (nonce+tag+ciphertext)
    halt 400, 'Invalid or empty result data. Shutting down to prevent potential abuse.'
  end

  result_file = "#{RESULTS_DIR}/#{uuid}.enc"
  processing  = "#{QUEUE_DIR}/#{uuid}.processing.json"

  # Write the already-encrypted data directly to disk
  File.binwrite(result_file, encrypted_data)

  # Clean up the processing marker
  File.delete(processing) if File.exist?(processing)

  status 200
  body ''
end
# ============== Internal: Poll for next job ==============

# Internal endpoint used by Innie to pull the next pending job.
#
# Returns 204 No Content if queue is empty.
get '/severance/queue/pull' do
  pending_files = Dir["#{QUEUE_DIR}/*.pending.json"].sort
  if pending_files.empty?
    status 204
    body ''
  else
    file = pending_files.first
    uuid = File.basename(file, '.pending.json')
    job_json = File.read(file)

    # Move to processing
    File.rename(file, "#{QUEUE_DIR}/#{uuid}.processing.json")

    # Add uuid to the response
    job = JSON.parse(job_json)
    job['uuid'] = uuid

    content_type 'application/json'
    body JSON.generate(job)
  end
end

# Optional helper route - health check / info
get '/severance' do
  "Outie service ready (v#{SEVERANCE_VERSION}). Use /severance/queries to submit jobs."
end

# Malformed JSON in a request body -- POST /severance/queries, the main
# externally-facing endpoint, had no rescue around its JSON.parse at all,
# so a caller sending broken JSON hit an unhandled exception (a generic
# 500, indistinguishable from a real server-side fault) rather than a
# clean 400. This is a catch-all safety net for any route in this file
# that doesn't already handle it locally (POST /severance/available_queries
# already has its own JSON::ParserError/InvalidBodyEncodingError rescue,
# kept as-is).
#
# InvalidBodyEncodingError is included here too: a body that parses as
# syntactically valid JSON but contains a string with an invalid UTF-8 byte
# sequence used to sail straight through JSON.parse (which does not
# validate encoding) and crash later -- with a full stack trace leaked to
# the caller -- the instant something as ordinary as `.strip` touched the
# tainted string (see `read_utf8_body!`, which now catches this up front).
error JSON::ParserError, InvalidBodyEncodingError do
  content_type 'application/json'
  status 400
  { error: 'invalid_json' }.to_json
end
