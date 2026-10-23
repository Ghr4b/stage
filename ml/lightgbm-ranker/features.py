"""
Feature pipeline for the LightGBM intra-tier ranker.

Extracts all BOD 26-04 variables, EPSS, CVSS (nullable), reachability,
asset criticality, exposure, plus nvd_enrichment_status and CVSS-presence
as explicit features.
"""

import json
from dataclasses import dataclass
from typing import Optional


@dataclass
class FindingFeatures:
    """Feature vector for a single finding."""
    # BOD 26-04 variables
    kev_listed: bool
    exposure_public: bool
    automatable: bool
    technical_impact_total: bool

    # CVSS (nullable — presence is a separate feature)
    cvss_score: Optional[float]
    cvss_present: bool  # Explicit feature: is CVSS data available?

    # EPSS
    epss_score: float

    # NVD enrichment status (explicit feature, not conflated with score)
    nvd_enrichment_status: str  # "enriched", "awaiting_analysis", "not_scheduled"

    # Asset context
    asset_criticality: str  # "mission_critical", "high_value", "standard", "low_value"
    reachable: bool

    # BOD tier (label/context, not a training feature)
    bod_tier: int


def extract_features(finding_json: dict) -> FindingFeatures:
    """Extract features from a normalized finding JSON object."""
    cvss = finding_json.get("cvss")
    cvss_score = None
    cvss_present = False
    if cvss is not None and cvss.get("score") is not None:
        cvss_score = float(cvss["score"])
        cvss_present = True

    epss = finding_json.get("epss", {})
    epss_score = float(epss.get("score", 0.0)) if epss else 0.0

    return FindingFeatures(
        kev_listed=finding_json.get("kev_listed", False),
        exposure_public=finding_json.get("exposure_public", True),  # conservative default
        automatable=finding_json.get("automatable", True),  # conservative default
        technical_impact_total=finding_json.get("technical_impact_total", True),
        cvss_score=cvss_score,
        cvss_present=cvss_present,
        epss_score=epss_score,
        nvd_enrichment_status=finding_json.get("nvd_enrichment_status", "not_scheduled"),
        asset_criticality=finding_json.get("asset_criticality", "standard"),
        reachable=finding_json.get("reachable", True),  # conservative default
        bod_tier=finding_json.get("bod_tier", 90),
    )


def features_to_vector(f: FindingFeatures) -> list:
    """Convert feature struct to a numeric vector for model input.

    IMPORTANT: cvss_present and nvd_enrichment_status are encoded as
    separate dimensions so the model can distinguish 'genuinely low CVSS'
    from 'never scored' — this is the P11-1 named test requirement.
    """
    criticality_map = {
        "mission_critical": 4,
        "high_value": 3,
        "standard": 2,
        "low_value": 1,
    }
    enrichment_map = {
        "enriched": 2,
        "awaiting_analysis": 1,
        "not_scheduled": 0,
    }

    return [
        int(f.kev_listed),
        int(f.exposure_public),
        int(f.automatable),
        int(f.technical_impact_total),
        f.cvss_score if f.cvss_score is not None else 0.0,
        int(f.cvss_present),  # <-- explicit dimension
        f.epss_score,
        enrichment_map.get(f.nvd_enrichment_status, 0),  # <-- explicit dimension
        criticality_map.get(f.asset_criticality, 2),
        int(f.reachable),
    ]
