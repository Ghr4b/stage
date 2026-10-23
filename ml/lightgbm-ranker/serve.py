"""
serve.py — Model serving and inference for the LightGBM intra-tier ranker.

Loads the current model and scores findings within a BOD 26-04 tier.
Invariant I9: scores ONLY reorder within a tier, never change tier assignment.
"""

import json
import os
import sys

try:
    import lightgbm as lgb
    import numpy as np
    HAS_LIGHTGBM = True
except ImportError:
    HAS_LIGHTGBM = False

from features import extract_features, features_to_vector


class ModelServer:
    """Serves predictions from a timestamped LightGBM model.

    P11-5: Supports rollback by loading any historical model version.
    P11-6: Early-stage weighting caps learned contribution when labeled data is scarce.
    """

    def __init__(self, model_dir: str, labeled_data_count: int = 0,
                 low_data_threshold: int = 500):
        self.model_dir = model_dir
        self.model = None
        self.metrics = None
        self.labeled_data_count = labeled_data_count
        self.low_data_threshold = low_data_threshold

        self._load_current_model()

    def _load_current_model(self):
        """Load the model pointed to by the 'current' symlink."""
        if not HAS_LIGHTGBM:
            return

        model_path = os.path.join(self.model_dir, "model_current.txt")
        metrics_path = os.path.join(self.model_dir, "metrics_current.json")

        if os.path.exists(model_path):
            self.model = lgb.Booster(model_file=model_path)
            print(f"Loaded model from {os.path.realpath(model_path)}")

        if os.path.exists(metrics_path):
            with open(metrics_path, "r") as f:
                self.metrics = json.load(f)

    def rollback_to(self, model_filename: str):
        """P11-5: Rollback to a specific historical model version."""
        if not HAS_LIGHTGBM:
            return

        model_path = os.path.join(self.model_dir, model_filename)
        if not os.path.exists(model_path):
            raise FileNotFoundError(f"Model {model_filename} not found")

        self.model = lgb.Booster(model_file=model_path)
        # Update symlink
        current_link = os.path.join(self.model_dir, "model_current.txt")
        if os.path.exists(current_link):
            os.remove(current_link)
        os.symlink(model_filename, current_link)

        # Load corresponding metrics
        metrics_filename = model_filename.replace("model_", "metrics_").replace(".txt", ".json")
        metrics_path = os.path.join(self.model_dir, metrics_filename)
        if os.path.exists(metrics_path):
            with open(metrics_path, "r") as f:
                self.metrics = json.load(f)
            current_metrics = os.path.join(self.model_dir, "metrics_current.json")
            if os.path.exists(current_metrics):
                os.remove(current_metrics)
            os.symlink(metrics_filename, current_metrics)

        print(f"Rolled back to {model_filename}")

    def compute_learned_weight(self) -> float:
        """P11-6: Early-stage weighting.
        Returns the weight the learned score should get in the composite.
        Low data → learned weight is small (< 10%).
        High data → learned weight grows."""
        if self.labeled_data_count < self.low_data_threshold:
            # Linear ramp from 0.02 to 0.10 as data grows toward threshold
            ratio = self.labeled_data_count / self.low_data_threshold
            return 0.02 + (0.08 * ratio)
        else:
            # Cap at 0.40 even with lots of data
            return min(0.40, 0.10 + 0.30 * (self.labeled_data_count / 10000))

    def score_finding(self, finding_json: dict) -> dict:
        """Score a single finding. Returns the composite ranking score and breakdown.

        I9 INVARIANT: The BOD tier is passed through unchanged. The learned score
        only affects ranking WITHIN the tier.
        """
        features = extract_features(finding_json)
        vector = features_to_vector(features)
        bod_tier = features.bod_tier  # NEVER modified by learned score

        if self.model is not None:
            learned_score = float(self.model.predict([vector])[0])
        else:
            learned_score = 0.5  # neutral when no model available

        learned_weight = self.compute_learned_weight()
        baseline_weight = 1.0 - learned_weight

        # Composite score for intra-tier ranking
        # Higher = higher priority within the tier
        epss_component = features.epss_score
        composite = (baseline_weight * epss_component) + (learned_weight * learned_score)

        return {
            "bod_tier": bod_tier,              # UNCHANGED — I9
            "composite_rank_score": round(composite, 6),
            "epss_component": round(epss_component, 6),
            "learned_component": round(learned_score, 6),
            "learned_weight": round(learned_weight, 4),
            "baseline_weight": round(baseline_weight, 4),
        }

    def rank_within_tier(self, findings: list[dict]) -> list[dict]:
        """Rank a list of findings within the same BOD tier.

        All findings MUST have the same bod_tier. Returns them sorted
        by composite score descending (highest priority first).
        """
        scored = []
        for f in findings:
            result = self.score_finding(f)
            scored.append({"finding": f, "score": result})

        # Verify I9: all findings have same tier
        tiers = set(s["score"]["bod_tier"] for s in scored)
        if len(tiers) > 1:
            raise ValueError(f"I9 violation: rank_within_tier called with mixed tiers: {tiers}")

        scored.sort(key=lambda x: x["score"]["composite_rank_score"], reverse=True)
        return scored
