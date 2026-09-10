"""
SecureCloud - Automated ML Model Training Pipeline
End-to-end training of multiple threat detection models, stratified splitting, model selection, and registry deployment.
"""

import os
import sys
import json
import hashlib
from datetime import datetime
from typing import Dict, Any, List, Optional, Callable

import pandas as pd
import numpy as np
import lightgbm
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier, HistGradientBoostingClassifier

# Add parent directory to path for imports
current_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.dirname(current_dir)
if parent_dir not in sys.path:
    sys.path.insert(0, parent_dir)

from ml.dataset_manager import DatasetManager
from ml.preprocessing import build_preprocessor, save_pipeline, NUMERIC_FEATURES, CATEGORICAL_FEATURES
from ml.evaluate_model import evaluate_pipeline, calculate_feature_importance
from ml.model_registry import ModelRegistry

RANDOM_STATE = 42

def train_threat_models(
    dataset_name: Optional[str] = None,
    progress_callback: Optional[Callable[[int, str, Optional[Dict[str, Any]]], None]] = None
) -> Dict[str, Any]:
    """
    Executes the 10-stage automated training pipeline.
    Optionally notifies progress_callback(stage_number, stage_description, payload).
    """
    def log_progress(step: int, msg: str, data: Optional[Dict[str, Any]] = None):
        print(f"[{step}/10] {msg}")
        if progress_callback:
            progress_callback(step, msg, data)

    # 1. Dataset Discovery
    log_progress(1, "Discovering security datasets in raw directory...")
    dm = DatasetManager(base_dir=current_dir)
    raw_df, actual_dataset_name = dm.load_raw_dataset(dataset_name)
    raw_path = os.path.join(dm.raw_dir, actual_dataset_name)

    with open(raw_path, "rb") as f:
        dataset_hash = hashlib.sha256(f.read()).hexdigest()

    # 2. Dataset Validation & Stats
    log_progress(2, f"Validating dataset '{actual_dataset_name}' ({len(raw_df)} rows)...")
    initial_analysis = dm.analyze_dataset(raw_df, target_col="label")

    # 3. Data Cleaning
    log_progress(3, "Executing automated data cleaning pipeline...")
    cleaned_df, clean_report = dm.clean_dataset(raw_df, target_col="label")
    cleaned_path = dm.save_cleaned_dataset(cleaned_df, actual_dataset_name)

    # 4. Preprocessing Setup
    log_progress(4, "Configuring ColumnTransformer and feature encoders...")
    target_col = clean_report["target_column"]
    
    # Ensure all required features are present
    for col in NUMERIC_FEATURES:
        if col not in cleaned_df.columns:
            cleaned_df[col] = 0.0
    for col in CATEGORICAL_FEATURES:
        if col not in cleaned_df.columns:
            cleaned_df[col] = "other"

    # 5. Feature Engineering / Matrix Preparation
    log_progress(5, "Structuring feature matrices and checking class distributions...")
    feature_cols = NUMERIC_FEATURES + CATEGORICAL_FEATURES
    X = cleaned_df[feature_cols].copy()
    y = cleaned_df[target_col].copy()

    class_counts = y.value_counts().to_dict()
    print(f"Class distribution: {class_counts}")

    # 6. Stratified Train / Validation / Test Splitting (70% / 15% / 15%)
    log_progress(6, "Splitting dataset into 70% Train, 15% Validation, 15% Test (Stratified)...")
    # First split 70% train, 30% temp
    X_train, X_temp, y_train, y_temp = train_test_split(
        X, y, test_size=0.30, random_state=RANDOM_STATE, stratify=y
    )
    # Split temp evenly into 15% validation and 15% test
    X_val, X_test, y_val, y_test = train_test_split(
        X_temp, y_temp, test_size=0.50, random_state=RANDOM_STATE, stratify=y_temp
    )

    # 7. Train Multiple Candidate Models
    log_progress(7, "Training multiple candidate threat classification models...")
    candidate_configs = [
        {
            "name": "LightGBM",
            "classifier": lightgbm.LGBMClassifier(
                n_estimators=150, learning_rate=0.08, max_depth=8, class_weight="balanced", random_state=RANDOM_STATE, verbose=-1
            )
        },
        {
            "name": "Random Forest",
            "classifier": RandomForestClassifier(
                n_estimators=120, max_depth=16, class_weight="balanced", random_state=RANDOM_STATE, n_jobs=-1
            )
        },
        {
            "name": "Gradient Boosting",
            "classifier": GradientBoostingClassifier(
                n_estimators=100, learning_rate=0.1, max_depth=6, random_state=RANDOM_STATE
            )
        },
        {
            "name": "HistGradientBoosting",
            "classifier": HistGradientBoostingClassifier(
                class_weight="balanced", max_iter=100, random_state=RANDOM_STATE
            )
        },
        {
            "name": "Logistic Regression",
            "classifier": LogisticRegression(
                max_iter=1500, class_weight="balanced", random_state=RANDOM_STATE
            )
        }
    ]

    leaderboard = []
    trained_pipelines = {}

    for cand in candidate_configs:
        model_name = cand["name"]
        clf = cand["classifier"]
        print(f"  Training {model_name}...")

        # Build end-to-end pipeline
        pipe = Pipeline(steps=[
            ("preprocessor", build_preprocessor()),
            ("classifier", clf)
        ])

        # Fit on training data
        pipe.fit(X_train, y_train)
        trained_pipelines[model_name] = pipe

        # Evaluate on validation data
        val_metrics = evaluate_pipeline(pipe, X_val, y_val)
        
        # Combined score prioritizing Malicious Recall and Macro F1
        score = (
            val_metrics["malicious_recall"] * 0.50 +
            val_metrics["f1_score"] * 0.30 +
            val_metrics["accuracy"] * 0.20
        )

        leaderboard.append({
            "model": model_name,
            "accuracy": val_metrics["accuracy"],
            "f1": val_metrics["f1_score"],
            "malicious_recall": val_metrics["malicious_recall"],
            "suspicious_recall": val_metrics["suspicious_recall"],
            "clean_recall": val_metrics["clean_recall"],
            "roc_auc": val_metrics["roc_auc"],
            "selection_score": round(score, 2),
            "val_metrics": val_metrics
        })

    # 8. Model Evaluation on Test Set
    log_progress(8, "Evaluating candidate models on holdout test set...")
    # Sort leaderboard by selection score descending
    leaderboard = sorted(leaderboard, key=lambda x: x["selection_score"], reverse=True)

    # 9. Model Selection
    log_progress(9, f"Selecting top model: {leaderboard[0]['model']} (Malicious Recall: {leaderboard[0]['malicious_recall']}%, F1: {leaderboard[0]['f1']}%)")
    best_candidate = leaderboard[0]
    best_model_name = best_candidate["model"]
    best_pipeline = trained_pipelines[best_model_name]

    # Final evaluation on holdout test set
    final_test_metrics = evaluate_pipeline(best_pipeline, X_test, y_test)
    feature_importances = calculate_feature_importance(best_pipeline, X_test, y_test)

    # 10. Model Saving & Registry Deployment
    log_progress(10, "Saving pipeline artifact and deploying to model registry...")
    registry = ModelRegistry(base_dir=current_dir)
    version_tag = registry.get_next_version_string()
    
    versioned_path = os.path.join(registry.models_dir, f"{version_tag}.joblib")
    active_path = os.path.join(registry.models_dir, "active_model.joblib")

    # Save both versioned file and active pointer file
    save_pipeline(best_pipeline, versioned_path)
    save_pipeline(best_pipeline, active_path)

    dataset_info = {
        "name": actual_dataset_name,
        "hash": dataset_hash[:16],
        "rows": len(cleaned_df)
    }

    registered_record = registry.register_model(
        version=version_tag,
        algorithm=best_model_name,
        model_path=versioned_path,
        metrics=final_test_metrics,
        dataset_info=dataset_info,
        feature_count=len(feature_cols),
        feature_importances=feature_importances,
        is_active=True
    )

    # Generate training report JSON
    report_data = {
        "timestamp": datetime.now().isoformat(),
        "version": version_tag,
        "selected_algorithm": best_model_name,
        "dataset": actual_dataset_name,
        "dataset_hash": dataset_hash,
        "total_rows": len(raw_df),
        "cleaned_rows": len(cleaned_df),
        "duplicates_removed": clean_report["duplicate_rows"],
        "class_distribution": class_counts,
        "leaderboard": leaderboard,
        "final_test_metrics": final_test_metrics,
        "feature_importances": feature_importances
    }

    report_path = os.path.join(dm.reports_dir, f"training_report_{version_tag}.json")
    with open(report_path, "w", encoding="utf-8") as f:
        json.dump(report_data, f, indent=2)

    print("\n" + "="*50)
    print("MODEL TRAINING & REGISTRATION COMPLETE")
    print(f"Active Model: {best_model_name} ({version_tag})")
    print(f"Accuracy: {final_test_metrics['accuracy']}%")
    print(f"F1 Score: {final_test_metrics['f1_score']}%")
    print(f"Malicious Threat Recall: {final_test_metrics['malicious_recall']}%")
    print("="*50)

    return report_data

if __name__ == "__main__":
    train_threat_models()
