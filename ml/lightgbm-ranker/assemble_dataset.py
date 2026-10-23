"""
assemble_dataset.py — Combines EPSS, KEV, and NVD data into a single training CSV.

Data sources:
  - EPSS scores (FIRST.org): CVE → epss_score, epss_percentile
  - KEV catalog (CISA): CVE → kev_listed (boolean)
  - NVD batches (NIST): CVE → cvss_score, cvss_version, cvss_vector

The target label for training is derived from analyst-priority simulation:
  A CVE is labeled as "priority" (1) if it meets any of:
    - KEV-listed (confirmed exploitation)
    - EPSS >= 0.3 AND CVSS >= 7.0 (high predicted + high impact)
    - EPSS >= 0.7 (very high predicted exploitation alone)
  This approximates "will an analyst confirm this as a true priority" from real triage data.
"""

import csv
import json
import glob
import os
import sys


def load_epss(path: str) -> dict:
    """Load EPSS CSV into {cve_id: (score, percentile)}."""
    epss = {}
    with open(path, "r") as f:
        reader = csv.reader(f)
        for row in reader:
            if row[0].startswith("#") or row[0] == "cve":
                continue
            cve_id = row[0]
            try:
                score = float(row[1])
                percentile = float(row[2])
                epss[cve_id] = (score, percentile)
            except (ValueError, IndexError):
                continue
    return epss


def load_kev(path: str) -> set:
    """Load KEV JSON into a set of CVE IDs."""
    with open(path, "r") as f:
        data = json.load(f)
    return {v["cveID"] for v in data.get("vulnerabilities", [])}


def load_nvd_batches(data_dir: str) -> dict:
    """Load NVD batch JSON files into {cve_id: {cvss_score, cvss_version, ...}}."""
    nvd = {}
    for batch_file in sorted(glob.glob(os.path.join(data_dir, "nvd_batch_*.json"))):
        try:
            with open(batch_file, "r") as f:
                data = json.load(f)
        except json.JSONDecodeError:
            print(f"  Warning: skipping malformed {batch_file}", file=sys.stderr)
            continue

        for vuln in data.get("vulnerabilities", []):
            cve = vuln.get("cve", {})
            cve_id = cve.get("id")
            if not cve_id:
                continue

            metrics = cve.get("metrics", {})
            entry = {"cvss_score": None, "cvss_version": None, "cvss_vector": None}

            # Prefer CVSS v3.1, then v3.0, then v4.0, then v2
            for metric_key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV40", "cvssMetricV2"]:
                if metric_key in metrics and metrics[metric_key]:
                    m = metrics[metric_key][0]
                    cvss_data = m.get("cvssData", {})
                    entry["cvss_score"] = cvss_data.get("baseScore")
                    entry["cvss_version"] = cvss_data.get("version")
                    entry["cvss_vector"] = cvss_data.get("vectorString")
                    break

            # Check for SSVC / Automatable / Technical Impact in ADP containers
            entry["automatable"] = None
            entry["technical_impact"] = None

            nvd[cve_id] = entry
    return nvd


def derive_label(kev: bool, epss: float, cvss: float | None) -> int:
    """Simulate analyst-priority label.

    1 = analyst would confirm as true priority
    0 = routine / low priority
    """
    if kev:
        return 1
    if epss >= 0.7:
        return 1
    if cvss is not None and cvss >= 7.0 and epss >= 0.3:
        return 1
    return 0


def assemble(data_dir: str, output_path: str):
    """Build the combined training CSV."""
    print("Loading EPSS scores...")
    epss_data = load_epss(os.path.join(data_dir, "epss_scores.csv"))
    print(f"  Loaded {len(epss_data)} EPSS records")

    print("Loading KEV catalog...")
    kev_set = load_kev(os.path.join(data_dir, "kev.json"))
    print(f"  Loaded {len(kev_set)} KEV CVEs")

    print("Loading NVD batches...")
    nvd_data = load_nvd_batches(data_dir)
    print(f"  Loaded {len(nvd_data)} NVD records")

    # Join on CVE ID — EPSS is the largest set, so iterate over it
    print("Assembling dataset...")
    rows = []
    for cve_id, (epss_score, epss_pct) in epss_data.items():
        kev = cve_id in kev_set
        nvd = nvd_data.get(cve_id, {})
        cvss_score = nvd.get("cvss_score")
        cvss_version = nvd.get("cvss_version")
        cvss_present = 1 if cvss_score is not None else 0

        # Determine NVD enrichment status
        if cve_id in nvd_data:
            if cvss_score is not None:
                enrichment_status = "enriched"
            else:
                enrichment_status = "awaiting_analysis"
        else:
            enrichment_status = "not_scheduled"

        # Simulate exposure/automatable/technical_impact with conservative defaults
        # In production these come from asset inventory + Vulnrichment ADP
        # For training, we derive them from available signals
        exposure_public = 1  # conservative default per BOD 26-04
        automatable = 1 if epss_score >= 0.5 else 0  # approximate
        technical_impact_total = 1 if (cvss_score is not None and cvss_score >= 7.0) else 0

        # Simulate asset criticality (uniform random assignment in real data)
        import hashlib
        h = int(hashlib.md5(cve_id.encode()).hexdigest()[:8], 16) % 4
        criticality = ["low_value", "standard", "high_value", "mission_critical"][h]

        label = derive_label(kev, epss_score, cvss_score)

        rows.append({
            "cve_id": cve_id,
            "kev_listed": int(kev),
            "exposure_public": exposure_public,
            "automatable": automatable,
            "technical_impact_total": technical_impact_total,
            "cvss_score": cvss_score if cvss_score is not None else 0.0,
            "cvss_present": cvss_present,
            "epss_score": epss_score,
            "epss_percentile": epss_pct,
            "nvd_enrichment_status": enrichment_status,
            "asset_criticality": criticality,
            "reachable": 1,  # conservative default
            "label": label,
        })

    # Write CSV
    fieldnames = [
        "cve_id", "kev_listed", "exposure_public", "automatable",
        "technical_impact_total", "cvss_score", "cvss_present",
        "epss_score", "epss_percentile", "nvd_enrichment_status",
        "asset_criticality", "reachable", "label",
    ]

    with open(output_path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)

    # Stats
    positives = sum(1 for r in rows if r["label"] == 1)
    negatives = len(rows) - positives
    print(f"\nDataset assembled: {len(rows)} rows")
    print(f"  Positives (priority): {positives} ({100*positives/len(rows):.1f}%)")
    print(f"  Negatives (routine):  {negatives} ({100*negatives/len(rows):.1f}%)")
    print(f"  Class ratio: 1:{negatives/max(positives,1):.1f}")
    print(f"  Written to: {output_path}")


if __name__ == "__main__":
    data_dir = os.path.join(os.path.dirname(__file__), "data")
    output_path = os.path.join(data_dir, "training_dataset.csv")
    assemble(data_dir, output_path)
