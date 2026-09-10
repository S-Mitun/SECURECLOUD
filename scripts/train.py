"""
SecureCloud - Command Line Model Training Launcher
"""

import os
import sys
from pathlib import Path

# Add root directory to sys.path
ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from ml.train_model import train_threat_models

if __name__ == "__main__":
    print("Launching SecureCloud Automated Threat Model Training Pipeline...")
    dataset_name = sys.argv[1] if len(sys.argv) > 1 else None
    train_threat_models(dataset_name=dataset_name)
