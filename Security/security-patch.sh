#!/bin/bash
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"

timestamp=$(date +"%Y-%m-%d")

# Archive the previous run's scan results instead of deleting them -- someone
# running an older patched image should still be able to look up what
# vulnerabilities apply to the version they actually have deployed.
mkdir -p ./security_scan_output/old
find ./security_scan_output -maxdepth 1 -type f \( -name '*.json' -o -name '*.csv' \) -exec mv {} ./security_scan_output/old/ \;

# Both Severance images are ours (built from ../external and ../internal in
# this repo), so each one gets built fresh from source first -- not just
# OS-patched on top of a stale previous build -- so any Dockerfile-level fix
# (a dependency bump, a hardening change) actually reaches the patched image,
# not only the OS package layer. The OS layer is then patched on top of that
# fresh build (shell in, apt update/dist-upgrade, commit) rather than baked
# into the Dockerfile itself, since re-running this script regularly is what
# actually keeps the OS layer current -- a Dockerfile-baked dist-upgrade
# would only be as fresh as whenever the Dockerfile itself was last built.
#
# All progress output below goes to stderr; the final `fairdatasystems/
# <name>:<timestamp>` tag is the only thing written to stdout, so callers can
# capture it with `tag=$(patch_image ...)` while still seeing live progress.
patch_image() {
  local name="$1" build_dir="$2" version_file="$3"
  local build_tag="${name}:build-${timestamp}"
  local outputfile="./security_scan_output/scanresults_${name}_${timestamp}.json"

  {
    echo ""
    echo "=== ${name} ==="
    echo "building ${build_tag} from ${build_dir}"
  } >&2
  docker build --build-arg SEVERANCE_VERSION="$(cat "${version_file}")" \
    -t "${build_tag}" "${build_dir}" >&2

  docker rm -f "${name}" >/dev/null 2>&1 || true
  # Both outie.rb and innie.rb now abort immediately if ENCRYPTION_KEY_HEX
  # isn't set (a deliberate fail-closed check, not a bug) -- without a real
  # value here the container's PID1 exits right after `docker run`, and
  # every `docker exec` below silently fails with "container is not
  # running" instead of actually patching anything. This key is thrown
  # away with the container once patching is done; it never serves real
  # traffic, so it doesn't need to be the deployment's real key.
  local patch_key
  patch_key=$(openssl rand -hex 32)
  docker run -d --name "${name}" -e "ENCRYPTION_KEY_HEX=${patch_key}" "${build_tag}" >&2
  sleep 2
  echo "updating ${name}" >&2
  docker exec "${name}" apt-get -y update >&2
  docker exec "${name}" apt-get -y dist-upgrade --fix-missing >&2
  docker start "${name}" >/dev/null 2>&1 || true
  docker exec "${name}" apt-get -y autoclean >&2
  echo "commit" >&2
  docker commit "${name}" "fairdatasystems/${name}:${timestamp}" >&2
  docker stop "${name}" >/dev/null
  docker rm "${name}" >/dev/null
  docker rmi "${build_tag}" >/dev/null 2>&1 || true
  echo "push" >&2
  docker push "fairdatasystems/${name}:${timestamp}" >&2
  echo "pushed" >&2
  echo "trivy" >&2
  trivy image --scanners vuln --format json --severity CRITICAL,HIGH --timeout 1800s \
    "fairdatasystems/${name}:${timestamp}" > "${outputfile}"
  echo "END" >&2

  echo "fairdatasystems/${name}:${timestamp}"
}

SIN=$(patch_image sevinternal ../internal ../internal/VERSION)
SOUT=$(patch_image sevexternal ../external ../external/VERSION)

cp inner-docker-compose-template-template.yml inner-docker-compose-template-tmp.yml
cp outer-docker-compose-template-template.yml outer-docker-compose-template-tmp.yml
sed -i'' -e "s!{SIN}!${SIN}!" "inner-docker-compose-template-tmp.yml"
sed -i'' -e "s!{SOUT}!${SOUT}!" "outer-docker-compose-template-tmp.yml"

mv inner-docker-compose-template-tmp.yml ../internal/docker-compose.yml
mv outer-docker-compose-template-tmp.yml ../external/docker-compose.yml

ruby parse-security-scans.rb ./security_scan_output/*.json
python3 build_register.py
