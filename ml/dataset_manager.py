"""
SecureCloud 2.0 - Dataset Management System
Automated discovery, validation, cleaning, and statistics generation.
"""

import os
import json
import numpy as np
import pandas as pd
from typing import Dict, Any, List, Optional, Tuple

class DatasetManager:
    """Manages raw, cleaned, and processed datasets for ML threat training."""

    def __init__(self, base_dir: Optional[str] = None):
        if base_dir is None:
            self.base_dir = os.path.dirname(os.path.abspath(__file__))
        else:
            self.base_dir = base_dir

        self.raw_dir = os.path.join(self.base_dir, "datasets", "raw")
        self.cleaned_dir = os.path.join(self.base_dir, "datasets", "cleaned")
        self.processed_dir = os.path.join(self.base_dir, "datasets", "processed")
        self.reports_dir = os.path.join(self.base_dir, "reports")
        self.logs_dir = os.path.join(self.base_dir, "logs")

        for d in [self.raw_dir, self.cleaned_dir, self.processed_dir, self.reports_dir, self.logs_dir]:
            os.makedirs(d, exist_ok=True)

        self.label_mapping = {
            "clean": "CLEAN",
            "benign": "CLEAN",
            "safe": "CLEAN",
            "normal": "CLEAN",
            "0": "CLEAN",
            0: "CLEAN",
            "suspicious": "SUSPICIOUS",
            "warning": "SUSPICIOUS",
            "risk": "SUSPICIOUS",
            "1": "SUSPICIOUS",
            1: "SUSPICIOUS",
            "malicious": "MALICIOUS",
            "malware": "MALICIOUS",
            "threat": "MALICIOUS",
            "danger": "MALICIOUS",
            "2": "MALICIOUS",
            2: "MALICIOUS"
        }

    def discover_datasets(self) -> List[Dict[str, Any]]:
        """Discovers available datasets in raw directory."""
        datasets = []
        if not os.path.exists(self.raw_dir):
            return datasets

        for filename in os.listdir(self.raw_dir):
            ext = os.path.splitext(filename)[1].lower()
            if ext in [".csv", ".json", ".parquet"]:
                full_path = os.path.join(self.raw_dir, filename)
                size_bytes = os.path.getsize(full_path)
                datasets.append({
                    "filename": filename,
                    "path": full_path,
                    "format": ext.replace(".", "").upper(),
                    "size_bytes": size_bytes,
                    "size_formatted": f"{size_bytes / (1024 * 1024):.2f} MB" if size_bytes >= 1024*1024 else f"{size_bytes / 1024:.2f} KB",
                    "modified_time": os.path.getmtime(full_path)
                })
        return datasets

    def load_raw_dataset(self, filename: Optional[str] = None) -> Tuple[pd.DataFrame, str]:
        """Loads a raw dataset file by name or loads the first discovered."""
        if not filename:
            discovered = self.discover_datasets()
            if not discovered:
                raise FileNotFoundError("Training dataset not found in ml/datasets/raw/.")
            target_path = discovered[0]["path"]
            filename = discovered[0]["filename"]
        else:
            target_path = os.path.join(self.raw_dir, filename)
            if not os.path.exists(target_path):
                # Check if it was provided as absolute path
                if os.path.exists(filename):
                    target_path = filename
                    filename = os.path.basename(filename)
                else:
                    raise FileNotFoundError(f"Dataset '{filename}' not found in {self.raw_dir}")

        ext = os.path.splitext(target_path)[1].lower()
        if ext == ".csv":
            df = pd.read_csv(target_path)
        elif ext == ".json":
            df = pd.read_json(target_path)
        elif ext == ".parquet":
            df = pd.read_parquet(target_path)
        else:
            raise ValueError(f"Unsupported dataset format: {ext}")

        return df, filename

    def analyze_dataset(self, df: pd.DataFrame, target_col: str = "label") -> Dict[str, Any]:
        """Generates comprehensive dataset statistics and quality analysis."""
        row_count = int(len(df))
        col_count = int(len(df.columns))
        duplicate_rows = int(df.duplicated().sum())
        missing_values = int(df.isnull().sum().sum())
        missing_per_col = {col: int(val) for col, val in df.isnull().sum().items() if val > 0}

        numeric_cols = [col for col in df.select_dtypes(include=[np.number]).columns if col != target_col]
        categorical_cols = [col for col in df.select_dtypes(include=["object", "category", "bool"]).columns if col != target_col]

        # Target label analysis
        label_detected = target_col in df.columns
        label_dist = {}

        if label_detected:
            raw_dist = df[target_col].value_counts().to_dict()
            for k, v in raw_dist.items():
                norm_key = self.label_mapping.get(str(k).lower(), str(k))
                label_dist[norm_key] = label_dist.get(norm_key, 0) + int(v)

        # Quality score calculation (0 - 100)
        quality_score = 100.0
        if row_count < 100:
            quality_score -= 20.0
        if duplicate_rows > 0:
            quality_score -= min(15.0, (duplicate_rows / max(row_count, 1)) * 50.0)
        if missing_values > 0:
            quality_score -= min(20.0, (missing_values / max(row_count * col_count, 1)) * 100.0)
        if not label_detected:
            quality_score -= 30.0

        quality_score = max(10.0, round(quality_score, 1))

        return {
            "row_count": row_count,
            "col_count": col_count,
            "duplicate_rows": duplicate_rows,
            "missing_values": missing_values,
            "missing_per_column": missing_per_col,
            "numeric_columns": numeric_cols,
            "categorical_columns": categorical_cols,
            "target_column": target_col,
            "has_target_column": label_detected,
            "class_distribution": label_dist,
            "quality_score": quality_score
        }

    def clean_dataset(self, df: pd.DataFrame, target_col: str = "label") -> Tuple[pd.DataFrame, Dict[str, Any]]:
        """
        Executes automatic cleaning pipeline:
        - Duplicate removal
        - Whitespace removal & column name normalization
        - Missing value imputation/handling
        - Infinite value correction
        - Target label validation and mapping
        """
        original_rows = len(df)
        initial_missing = int(df.isnull().sum().sum())

        # 1. Normalize column names (lowercase, stripped, alphanumeric/underscores)
        df_clean = df.copy()
        df_clean.columns = [str(c).strip().lower().replace(" ", "_").replace("-", "_") for c in df_clean.columns]
        target_col_norm = target_col.strip().lower().replace(" ", "_").replace("-", "_")

        # 2. Deduplicate rows
        df_clean = df_clean.drop_duplicates()
        duplicate_rows_removed = original_rows - len(df_clean)

        # 3. Strip whitespace from string/object columns
        str_cols = df_clean.select_dtypes(include=["object"]).columns
        for col in str_cols:
            df_clean[col] = df_clean[col].astype(str).str.strip()

        # 4. Handle target column mapping and validation
        if target_col_norm in df_clean.columns:
            # Map labels to conceptual classes: CLEAN, SUSPICIOUS, MALICIOUS
            mapped_labels = df_clean[target_col_norm].apply(
                lambda x: self.label_mapping.get(str(x).lower(), str(x).upper())
            )
            # Filter out invalid/unknown labels that do not map to valid set
            valid_mask = mapped_labels.isin(["CLEAN", "SUSPICIOUS", "MALICIOUS"])
            invalid_rows_count = int((~valid_mask).sum())
            df_clean = df_clean[valid_mask].copy()
            df_clean[target_col_norm] = mapped_labels[valid_mask]
        else:
            invalid_rows_count = 0

        # 5. Handle infinite and malformed values in numeric columns
        num_cols = df_clean.select_dtypes(include=[np.number]).columns
        for col in num_cols:
            df_clean[col] = df_clean[col].replace([np.inf, -np.inf], np.nan)
            # Impute median for remaining NaNs
            median_val = df_clean[col].median()
            if pd.isna(median_val):
                median_val = 0.0
            df_clean[col] = df_clean[col].fillna(median_val)

        # 6. Handle categorical missing values
        cat_cols = [c for c in df_clean.select_dtypes(include=["object"]).columns if c != target_col_norm]
        for col in cat_cols:
            mode_val = df_clean[col].mode()
            fill_val = mode_val[0] if len(mode_val) > 0 else "unknown"
            df_clean[col] = df_clean[col].fillna(fill_val)

        final_rows = len(df_clean)
        report = {
            "original_rows": original_rows,
            "duplicate_rows": duplicate_rows_removed,
            "invalid_rows": invalid_rows_count,
            "missing_values_handled": initial_missing,
            "final_rows": final_rows,
            "columns": list(df_clean.columns),
            "target_column": target_col_norm,
            "class_distribution": df_clean[target_col_norm].value_counts().to_dict() if target_col_norm in df_clean.columns else {}
        }

        return df_clean, report

    def save_cleaned_dataset(self, df: pd.DataFrame, filename: str) -> str:
        """Saves the cleaned dataset to the cleaned directory."""
        clean_path = os.path.join(self.cleaned_dir, f"cleaned_{filename}")
        df.to_csv(clean_path, index=False)
        return clean_path
