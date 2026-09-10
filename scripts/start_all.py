"""
SecureCloud - Master Orchestration and Startup Script
"Secure Storage. Intelligent Protection."
"""

import os
import sys
import time
import subprocess
from pathlib import Path

# Add root directory to sys.path
ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from scripts.init_db import initialize_database
from ml.model_registry import ModelRegistry
from ml.train_model import train_threat_models
from scripts.generate_dataset import generate_security_dataset

def bootstrap_and_start():
    print("=" * 70)
    print("SECURECLOUD")
    print("=" * 70)

    # 1. Initialize DB & Storage
    print("\n[*] Initializing Database and Vault Storage...")
    initialize_database()

    # 2. Check Dataset
    raw_dataset_path = ROOT_DIR / "ml" / "datasets" / "raw" / "security_dataset.csv"
    if not os.path.exists(raw_dataset_path):
        print("\n[*] Generating initial security training dataset...")
        generate_security_dataset(str(raw_dataset_path), total_records=12000)

    # 3. Check ML Model
    registry = ModelRegistry()
    active_model = registry.get_active_model_info()
    if not active_model:
        print("\n[*] Training baseline threat detection models...")
        train_threat_models()
    else:
        print(f"\n[*] Active Production Model: {active_model.get('algorithm')} ({active_model.get('version')})")
        print(f"    Accuracy: {active_model.get('accuracy')}% | Malicious Recall: {active_model.get('malicious_recall')}%")

    # 4. Start Server
    print("\n" + "=" * 70)
    print("STARTING SECURECLOUD SERVER")
    print("Application URL: http://127.0.0.1:8000")
    print("Prometheus Metrics: http://127.0.0.1:8000/metrics")
    print("Default Admin Credentials: admin@securecloud.com / AdminPass123!")
    print("Default User Credentials:  analyst@securecloud.com / UserPass123!")
    print("=" * 70 + "\n")

    import uvicorn
    uvicorn.run("backend.app.main:app", host="127.0.0.1", port=8000, reload=False)

if __name__ == "__main__":
    bootstrap_and_start()
