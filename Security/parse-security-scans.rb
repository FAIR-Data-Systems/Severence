require 'json'
require 'csv'

def parse_trivy_json(output)
  # Parse Trivy JSON output and filter for CRITICAL and HIGH vulnerabilities.
  # Expects JSON with a 'Results' key containing an array of result objects.

  data = JSON.parse(output)
  filtered_vulns = []
  results = data['Results'] || []
  return nil, 'JSON does not contain "Results" key. Ensure input is valid Trivy JSON output.' unless data['Results']

  results.each do |result|
    next unless result['Vulnerabilities'] # Skip if no vulnerabilities

    result['Vulnerabilities'].each do |vuln|
      severity = vuln['Severity']&.upcase
      next unless %w[CRITICAL HIGH].include?(severity)

      filtered_vulns << {
        'Target' => result['Target'] || 'Unknown',
        'VulnerabilityID' => vuln['VulnerabilityID'] || 'N/A',
        'PkgName' => vuln['PkgName'] || 'N/A',
        'InstalledVersion' => vuln['InstalledVersion'] || 'N/A',
        'FixedVersion' => vuln['FixedVersion'] || 'N/A',
        'Severity' => severity,
        'Title' => vuln['Title'] || 'N/A',
        'PrimaryURL' => vuln['PrimaryURL'] || 'N/A'
      }
    end
  end
  [filtered_vulns, nil]
rescue JSON::ParserError
  [nil, 'Invalid JSON format. Ensure input is valid Trivy JSON output.']
end

def write_csv_output(vulns, output_file)
  # Write filtered vulnerabilities to a CSV file for spreadsheet use.
  #
  # If there's nothing to report, remove any stale CSV left over from a
  # previous run instead of just skipping the write -- a rescan that
  # resolved every CRITICAL/HIGH finding for an image must not leave the
  # old (now-wrong) CSV sitting on disk to be silently read by
  # build_register.py as if it were still current. Hit this for real in
  # Sextans-Suite (see that project's VULNERABILITY_TRIAGE.md) before this
  # fix existed.
  if vulns.empty?
    removed = File.delete(output_file) if File.exist?(output_file)
    return if removed.nil?

    return "No CRITICAL or HIGH vulnerabilities found. Removed stale '#{output_file}' from a previous run."
  end

  headers = %w[Target VulnerabilityID Package InstalledVersion FixedVersion Severity Title
               PrimaryURL]
  CSV.open(output_file, 'w') do |csv|
    csv << headers
    vulns.each do |vuln|
      csv << [
        vuln['Target'],
        vuln['VulnerabilityID'],
        vuln['PkgName'],
        vuln['InstalledVersion'],
        vuln['FixedVersion'],
        vuln['Severity'],
        vuln['Title'],
        vuln['PrimaryURL']
      ]
    end
  end

  critical_count = vulns.count { |v| v['Severity'] == 'CRITICAL' }
  high_count = vulns.count { |v| v['Severity'] == 'HIGH' }
  "Generated CSV file '#{output_file}' with #{vulns.length} vulnerabilities (CRITICAL: #{critical_count}, HIGH: #{high_count})."
end

# Check for valid input
if ARGV.empty?
  puts 'Usage: ruby parse-security-scans.rb <trivy_output.json> [trivy_output2.json ...] or glob pattern (e.g., ./scans/*.json)'
  exit 1
end

# Process all files matching the provided arguments (supports glob patterns)
files = ARGV.flat_map { |arg| Dir.glob(arg) }.uniq
if files.empty?
  puts 'Error: No JSON files found matching the provided pattern(s).'
  exit 1
end

files.each do |file|
  puts "\nProcessing #{file}..."
  begin
    output = File.read(file)
  rescue Errno::ENOENT
    puts "Error: File '#{file}' not found."
    next
  end

  # Parse JSON
  vulns, error = parse_trivy_json(output)
  if error
    puts "Error for #{file}: #{error}"
    next
  end

  # Generate output CSV filename (replace .json with .csv)
  output_file = File.join(File.dirname(file), File.basename(file, '.json') + '.csv')

  # Write CSV and print result
  result = write_csv_output(vulns, output_file)
  puts result unless result.nil?
end
