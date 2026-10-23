"""
train.py — LightGBM intra-tier ranker training pipeline.

Trains a gradient-boosted classifier that predicts analyst-confirmed priority
within a BOD 26-04 tier. The model is used to RANK findings within a tier,
never to change tier assignments (invariant I9).

Key design decisions per ARCHITECTURE_FINAL.md §10:
  - scale_pos_weight computed from class ratio (not left at default 1.0)
  - Conservative num_leaves to prevent overfitting on small datasets
  - nvd_enrichment_status and cvss_present as explicit features (P11-1)
  - Validation gate: new model must beat current model on held-out FPR/recall
"""

import csv
import json
import os
import sys
import time
from datetime import datetime

try:
    import lightgbm as lgb
    import numpy as np
    HAS_LIGHTGBM = True
except ImportError:
    HAS_LIGHTGBM = False
    print("WARNING: lightgbm/numpy not installed. Install with: pip install lightgbm numpy", file=sys.stderr)


# Feature columns (must match features.py encoding order)
FEATURE_COLUMNS = [
    "kev_listed",
    "exposure_public",
    "automatable",
    "technical_impact_total",
    "cvss_score",
    "cvss_present",
    "epss_score",
    "nvd_enrichment_status",  # encoded as int
    "asset_criticality",      # encoded as int
    "reachable",
]

ENRICHMENT_MAP = {"enriched": 2, "awaiting_analysis": 1, "not_scheduled": 0}
CRITICALITY_MAP = {"mission_critical": 4, "high_value": 3, "standard": 2, "low_value": 1}

LABEL_COLUMN = "label"


def load_dataset(csv_path: str):
    """Load the assembled CSV and return (X, y) as numpy arrays."""
    if not HAS_LIGHTGBM:
        raise RuntimeError("lightgbm/numpy required for training")

    X_rows = []
    y_rows = []

    with open(csv_path, "r") as f:
        reader = csv.DictReader(f)
        for row in reader:
            features = [
                int(row["kev_listed"]),
                int(row["exposure_public"]),
                int(row["automatable"]),
                int(row["technical_impact_total"]),
                float(row["cvss_score"]),
                int(row["cvss_present"]),
                float(row["epss_score"]),
                ENRICHMENT_MAP.get(row["nvd_enrichment_status"], 0),
                CRITICALITY_MAP.get(row["asset_criticality"], 2),
                int(row["reachable"]),
            ]
            X_rows.append(features)
            y_rows.append(int(row["label"]))

    return np.array(X_rows, dtype=np.float64), np.array(y_rows, dtype=np.int32)


def compute_scale_pos_weight(y) -> float:
    """Compute scale_pos_weight from class distribution.
    P11-2: Must NOT be left at default 1.0 on imbalanced data."""
    n_pos = np.sum(y == 1)
    n_neg = np.sum(y == 0)
    if n_pos == 0:
        return 1.0
    weight = n_neg / n_pos
    print(f"  Class balance: {n_neg} negative / {n_pos} positive = scale_pos_weight={weight:.2f}")
    return weight


def train_model(X_train, y_train, X_val, y_val, model_dir: str) -> dict:
    """Train LightGBM and save with validation metrics."""
    weight = compute_scale_pos_weight(y_train)

    params = {
        "objective": "binary",
        "metric": ["binary_logloss", "auc"],
        "boosting_type": "gbdt",
        "num_leaves": 31,           # Conservative per P11-2
        "learning_rate": 0.05,
        "feature_fraction": 0.8,
        "bagging_fraction": 0.8,
        "bagging_freq": 5,
        "scale_pos_weight": weight,  # P11-2: NOT default 1.0
        "verbose": -1,
        "seed": 42,
    }

    train_data = lgb.Dataset(X_train, label=y_train, feature_name=FEATURE_COLUMNS)
    val_data = lgb.Dataset(X_val, label=y_val, feature_name=FEATURE_COLUMNS, reference=train_data)

    print("\nTraining LightGBM...")
    callbacks = [lgb.log_evaluation(period=50)]
    model = lgb.train(
        params,
        train_data,
        num_boost_round=500,
        valid_sets=[train_data, val_data],
        valid_names=["train", "val"],
        callbacks=callbacks,
    )

    # Compute validation metrics
    y_pred_proba = model.predict(X_val)
    y_pred = (y_pred_proba >= 0.5).astype(int)

    tp = np.sum((y_pred == 1) & (y_val == 1))
    fp = np.sum((y_pred == 1) & (y_val == 0))
    fn = np.sum((y_pred == 0) & (y_val == 1))
    tn = np.sum((y_pred == 0) & (y_val == 0))

    recall = tp / max(tp + fn, 1)
    fpr = fp / max(fp + tn, 1)
    precision = tp / max(tp + fp, 1)
    accuracy = (tp + tn) / len(y_val)

    metrics = {
        "accuracy": float(accuracy),
        "recall": float(recall),
        "fpr": float(fpr),
        "precision": float(precision),
        "tp": int(tp), "fp": int(fp), "fn": int(fn), "tn": int(tn),
        "scale_pos_weight": float(weight),
        "num_boost_round": model.num_trees(),
        "feature_importances": dict(zip(FEATURE_COLUMNS, [int(x) for x in model.feature_importance()])),
    }

    print(f"\n--- Validation Metrics ---")
    print(f"  Accuracy:  {accuracy:.4f}")
    print(f"  Recall:    {recall:.4f}")
    print(f"  FPR:       {fpr:.4f}")
    print(f"  Precision: {precision:.4f}")
    print(f"  Feature importances: {metrics['feature_importances']}")

    # Save model with timestamp (P11-5: rollback-capable)
    timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    model_path = os.path.join(model_dir, f"model_{timestamp}.txt")
    model.save_model(model_path)

    # Save metrics alongside model
    metrics_path = os.path.join(model_dir, f"metrics_{timestamp}.json")
    with open(metrics_path, "w") as f:
        json.dump(metrics, f, indent=2)

    # Update "current" symlink (P11-5)
    current_link = os.path.join(model_dir, "model_current.txt")
    current_metrics = os.path.join(model_dir, "metrics_current.json")
    if os.path.exists(current_link):
        os.remove(current_link)
    if os.path.exists(current_metrics):
        os.remove(current_metrics)
    os.symlink(os.path.basename(model_path), current_link)
    os.symlink(os.path.basename(metrics_path), current_metrics)

    print(f"\n  Model saved: {model_path}")
    print(f"  Metrics saved: {metrics_path}")
    print(f"  Current symlink → {os.path.basename(model_path)}")

    return metrics


def validation_gate(new_metrics: dict, current_metrics_path: str) -> bool:
    """P11-4: Retraining validation gate.
    New model must have FPR <= current AND recall >= current to be promoted."""
    if not os.path.exists(current_metrics_path):
        print("  No existing model — promoting new model by default.")
        return True

    with open(current_metrics_path, "r") as f:
        current = json.load(f)

    print(f"\n--- Validation Gate ---")
    print(f"  Current: FPR={current['fpr']:.4f}, Recall={current['recall']:.4f}")
    print(f"  New:     FPR={new_metrics['fpr']:.4f}, Recall={new_metrics['recall']:.4f}")

    passes = (new_metrics["fpr"] <= current["fpr"] and
              new_metrics["recall"] >= current["recall"])

    if passes:
        print("  ✅ GATE PASSED — new model promoted")
    else:
        print("  ❌ GATE FAILED — new model BLOCKED, keeping current")

    return passes


def main():
    data_dir = os.path.join(os.path.dirname(__file__), "data")
    model_dir = os.path.join(os.path.dirname(__file__), "models")
    os.makedirs(model_dir, exist_ok=True)

    csv_path = os.path.join(data_dir, "training_dataset.csv")
    if not os.path.exists(csv_path):
        print(f"ERROR: {csv_path} not found. Run assemble_dataset.py first.", file=sys.stderr)
        sys.exit(1)

    if not HAS_LIGHTGBM:
        print("ERROR: lightgbm/numpy not installed.", file=sys.stderr)
        sys.exit(1)

    print("Loading dataset...")
    X, y = load_dataset(csv_path)
    print(f"  Total samples: {len(y)}")
    print(f"  Features: {X.shape[1]}")

    # 80/20 train/val split (deterministic)
    np.random.seed(42)
    indices = np.random.permutation(len(y))
    split = int(0.8 * len(y))
    train_idx, val_idx = indices[:split], indices[split:]

    X_train, y_train = X[train_idx], y[train_idx]
    X_val, y_val = X[val_idx], y[val_idx]

    print(f"  Train: {len(y_train)} samples")
    print(f"  Val:   {len(y_val)} samples")

    # Check for existing model (for validation gate)
    current_metrics_path = os.path.join(model_dir, "metrics_current.json")
    has_existing = os.path.exists(current_metrics_path)

    # Train
    new_metrics = train_model(X_train, y_train, X_val, y_val, model_dir)

    # Validation gate (P11-4)
    if has_existing:
        if not validation_gate(new_metrics, current_metrics_path):
            print("\nModel NOT promoted. Existing model retained.")
            sys.exit(1)

    print("\n✅ Training complete. Model is live.")


if __name__ == "__main__":
    main()
