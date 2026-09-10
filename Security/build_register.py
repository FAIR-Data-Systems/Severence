#!/usr/bin/env python3
"""
Builds/updates vulnerability-register.csv from the Trivy scan CSVs in
security_scan_output/. Existing decisions in the register are preserved
across re-runs (keyed on Image+VulnerabilityID); only genuinely new
CVE/image combinations get a fresh default disposition and land in the
"needs review" bucket.

Usage: python3 build_register.py
"""
import csv
import glob
import os
import collections

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
SCAN_DIR = os.path.join(SCRIPT_DIR, "security_scan_output")
REGISTER_PATH = os.path.join(SCRIPT_DIR, "vulnerability-register.csv")

# Static per-image classification. Update this as the fleet changes.
# exposure: 1 = network-exposed (directly or one hop via a proxy in front
#               of it)
#           2 = internal-only (reachable only from other containers on the
#               private network, or not currently deployed at all)
#           3 = inert (bundled but never invoked by our deployment)
# control:  owned   = we build this image ourselves from source in this
#                      repo -- every finding is ours to patch directly
IMAGE_INFO = {
    "sevexternal": {"exposure": 1, "control": "owned",
                     "note": "External: the DMZ-facing component. Publishes port 3000 "
                              "directly to the network by design (the whole point of "
                              "Severance's 'severed' model is that this is the only side "
                              "anything outside the secure zone ever talks to). Built from "
                              "our own Dockerfile (external/Dockerfile) -- every finding "
                              "here is ours to patch directly, at the OS layer (this "
                              "pipeline) or the app layer (Gemfile/Dockerfile changes)."},
    "sevinternal": {"exposure": 2, "control": "owned",
                     "note": "Internal: the polling component that talks to the triplestore. "
                              "Never listens on a port (see internal/docker-compose.yml -- no "
                              "network_mode: host, no ports: mapping) and only ever makes "
                              "outbound requests to External and the configured "
                              "TRIPLESTORE_URL, both of which should be on a private/internal "
                              "network in a real deployment. Built from our own Dockerfile "
                              "(internal/Dockerfile) -- every finding here is ours to patch "
                              "directly."},
}

# Manually researched dispositions for CVEs that need individual judgment,
# applying across every image they appear in unless overridden by a more
# specific (Image, VulnerabilityID) key. Empty until a real scan surfaces
# something that needs this -- see VULNERABILITY_TRIAGE.md for how/when to
# add entries here.
MANUAL_DECISIONS = {}

DEFAULT_DECISIONS = {
    (1, "owned"): ("PATCH", "Network-exposed, and we build this image directly -- patch "
                             "immediately (bump the pinned dependency, or confirm the next "
                             "security-patch.sh run's OS-level dist-upgrade already resolves "
                             "it)."),
    (2, "owned"): ("PATCH", "Internal-only, and we build this image directly -- patch at "
                             "the next opportunity; lower urgency than (1, owned) given no "
                             "direct network exposure, but still ours to fix, not to track."),
}


def load_rows():
    rows = collections.defaultdict(lambda: {
        "packages": set(), "installed": set(), "fixed": set(),
        "severity": None, "title": None, "url": None,
    })
    # Only the current run's CSVs live directly in SCAN_DIR (non-recursive glob);
    # everything superseded gets moved into SCAN_DIR/old/ by security-patch.sh
    # and is intentionally excluded from the register.
    for path in sorted(glob.glob(os.path.join(SCAN_DIR, "*.csv"))):
        image = os.path.basename(path).split("_")[1]
        with open(path, newline="") as f:
            for row in csv.DictReader(f):
                key = (image, row["VulnerabilityID"])
                agg = rows[key]
                agg["packages"].add(row["Package"])
                agg["installed"].add(row["InstalledVersion"])
                fv = row["FixedVersion"].strip()
                if fv and fv != "N/A":
                    agg["fixed"].add(fv)
                agg["severity"] = row["Severity"]
                agg["title"] = row["Title"]
                agg["url"] = row["PrimaryURL"]
    return rows


def load_existing_decisions():
    existing = {}
    if os.path.exists(REGISTER_PATH):
        with open(REGISTER_PATH, newline="") as f:
            for row in csv.DictReader(f):
                key = (row["Image"], row["VulnerabilityID"])
                existing[key] = (row["Decision"], row["Notes"])
    return existing


def main():
    rows = load_rows()
    existing = load_existing_decisions()

    out_rows = []
    for (image, cve), agg in sorted(rows.items()):
        info = IMAGE_INFO[image]
        exposure, control = info["exposure"], info["control"]

        if (image, cve) in existing:
            decision, notes = existing[(image, cve)]
        elif cve in MANUAL_DECISIONS:
            decision, notes = MANUAL_DECISIONS[cve]
        else:
            decision, notes = DEFAULT_DECISIONS[(exposure, control)]

        out_rows.append({
            "Image": image,
            "VulnerabilityID": cve,
            "Severity": agg["severity"],
            "ExposureTier": exposure,
            "Control": control,
            "Package": "; ".join(sorted(agg["packages"])),
            "InstalledVersion": "; ".join(sorted(agg["installed"])),
            "FixedVersion": "; ".join(sorted(agg["fixed"])) or "N/A",
            "Decision": decision,
            "Notes": notes,
            "Title": agg["title"],
            "PrimaryURL": agg["url"],
        })

    # Sort: CRITICAL first, then by exposure tier, then image, then CVE
    sev_rank = {"CRITICAL": 0, "HIGH": 1}
    out_rows.sort(key=lambda r: (sev_rank.get(r["Severity"], 9), r["ExposureTier"],
                                  r["Image"], r["VulnerabilityID"]))

    fieldnames = ["Image", "VulnerabilityID", "Severity", "ExposureTier", "Control",
                  "Package", "InstalledVersion", "FixedVersion", "Decision", "Notes",
                  "Title", "PrimaryURL"]
    with open(REGISTER_PATH, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(out_rows)

    counts = collections.Counter(r["Decision"] for r in out_rows)
    print(f"Wrote {len(out_rows)} rows to {REGISTER_PATH}")
    for d, n in counts.most_common():
        print(f"  {d}: {n}")


if __name__ == "__main__":
    main()
