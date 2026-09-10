"""
SecureCloud - ML Data Preprocessing Pipeline
Scikit-learn ColumnTransformer and Pipeline for consistent training and inference transformations.
"""

import os
import joblib
import pandas as pd
import numpy as np
from typing import Tuple, List, Optional
from sklearn.compose import ColumnTransformer
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler, OneHotEncoder
from sklearn.impute import SimpleImputer

# Standard feature set
NUMERIC_FEATURES = [
    "file_size",
    "file_entropy",
    "mime_mismatch",
    "filename_length",
    "filename_complexity",
    "special_char_count",
    "is_hidden",
    "is_executable_ext",
    "is_script_ext",
    "is_macro_ext",
    "is_archive_ext",
    "has_double_extension",
    "is_dangerous_extension",
    "suspicious_string_count",
    "suspicious_url_count",
    "suspicious_cmd_count",
    "powershell_indicator",
    "javascript_indicator",
    "vba_macro_indicator",
    "obfuscation_score",
    "encoded_content_indicator",
    "eval_indicator",
    "nested_archive_depth",
    "archive_has_executable",
    "archive_has_script",
    "compression_ratio",
    "non_ascii_ratio",
    "magic_entropy",
    "magic_is_pe"
]

CATEGORICAL_FEATURES = [
    "extension_category"
]

def build_preprocessor() -> ColumnTransformer:
    """Builds a scikit-learn ColumnTransformer for feature transformations."""
    numeric_transformer = Pipeline(steps=[
        ("imputer", SimpleImputer(strategy="median")),
        ("scaler", StandardScaler())
    ])

    categorical_transformer = Pipeline(steps=[
        ("imputer", SimpleImputer(strategy="most_frequent")),
        ("onehot", OneHotEncoder(handle_unknown="ignore", sparse_output=False))
    ])

    preprocessor = ColumnTransformer(
        transformers=[
            ("num", numeric_transformer, NUMERIC_FEATURES),
            ("cat", categorical_transformer, CATEGORICAL_FEATURES)
        ],
        remainder="drop"
    )
    return preprocessor

def save_pipeline(pipeline: Pipeline, path: str):
    """Saves a fitted scikit-learn pipeline to disk."""
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    joblib.dump(pipeline, path)

def load_pipeline(path: str) -> Pipeline:
    """Loads a saved pipeline from disk."""
    if not os.path.exists(path):
        raise FileNotFoundError(f"Model pipeline not found at {path}")
    return joblib.load(path)
