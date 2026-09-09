with open("backend/app/api/soc.py", "r", encoding="utf-8") as f:
    text = f.read()

old_func_start = """    from backend.app.services.crypto_service import compute_hashes
    from backend.app.services.feature_extractor import extract_file_features
    from backend.app.services.ml_detector import predict_threat
    from backend.app.services.storage_service import generate_storage_path, sanitize_filename
    from backend.app.models.models import VerifiedCleanArtifact"""

new_func_start = """    from backend.app.services.storage_service import (
        compute_hashes, format_size, sanitize_filename, generate_storage_path, recalculate_user_storage
    )
    from backend.app.models.models import VerifiedCleanArtifact
    from ml.predict import ThreatPredictor
    predictor = ThreatPredictor()"""

text = text.replace(old_func_start, new_func_start)

# Update scan_result prediction call
text = text.replace(
    """        features = extract_file_features(raw_bytes, clean_filename)
        scan_result = predict_threat(features)""",
    """        scan_result = predictor.predict(raw_bytes, clean_filename)"""
)

with open("backend/app/api/soc.py", "w", encoding="utf-8") as f:
    f.write(text)

print("[OK] Updated soc.py upload-for-user with correct predictor imports!")
