"""
SecureCloud - Security Dataset Generator
Generates a realistic 12,000-record cybersecurity threat dataset with authentic feature correlations.
"""

import os
import random
import numpy as np
import pandas as pd

random.seed(42)
np.random.seed(42)

def generate_security_dataset(output_path: str, total_records: int = 12000):
    """Generates synthetic security training dataset."""
    os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)

    records = []

    # Clean file types: PDF, DOCX, XLSX, TXT, CSV, PNG, JPG, MP3, MP4, ZIP
    # Suspicious types: PS1, JS, BAT, VBS, DOCM, XLSM
    # Malicious types: EXE, DLL, SCR, Double-ext, disguised binaries

    clean_count = int(total_records * 0.75) # 9,000
    suspicious_count = int(total_records * 0.15) # 1,800
    malicious_count = total_records - clean_count - suspicious_count # 1,200

    # 1. Generate CLEAN records
    clean_exts = [".pdf", ".docx", ".xlsx", ".pptx", ".txt", ".csv", ".json", ".xml", ".png", ".jpg", ".mp3", ".mp4", ".zip"]
    for _ in range(clean_count):
        ext = random.choice(clean_exts)
        size = int(np.random.lognormal(mean=11.5, sigma=1.8)) # 10KB to 20MB
        size = max(512, min(size, 80 * 1024 * 1024))
        entropy = round(np.random.normal(loc=4.8, scale=0.9), 4)
        entropy = max(1.5, min(6.8, entropy))
        
        filename_len = random.randint(8, 35)
        spec_chars = random.randint(0, 3)
        complexity = round(spec_chars / max(filename_len, 1), 4)

        records.append({
            "file_size": size,
            "file_entropy": entropy,
            "mime_mismatch": 0,
            "filename_length": filename_len,
            "filename_complexity": complexity,
            "special_char_count": spec_chars,
            "is_hidden": 1 if random.random() < 0.02 else 0,
            "is_executable_ext": 0,
            "is_script_ext": 0,
            "is_macro_ext": 0,
            "is_archive_ext": 1 if ext == ".zip" else 0,
            "has_double_extension": 0,
            "is_dangerous_extension": 0,
            "suspicious_string_count": random.choice([0, 0, 0, 0, 1]),
            "suspicious_url_count": random.randint(0, 2),
            "suspicious_cmd_count": 0,
            "powershell_indicator": 0,
            "javascript_indicator": 0,
            "vba_macro_indicator": 0,
            "obfuscation_score": round(random.uniform(0.0, 0.15), 2),
            "encoded_content_indicator": 0,
            "eval_indicator": 0,
            "nested_archive_depth": 0,
            "archive_has_executable": 0,
            "archive_has_script": 0,
            "compression_ratio": round(random.uniform(1.0, 2.5), 2) if ext == ".zip" else 1.0,
            "non_ascii_ratio": round(random.uniform(0.05, 0.35), 4),
            "magic_entropy": round(random.uniform(2.0, 5.0), 4),
            "magic_is_pe": 0,
            "extension_category": "document" if ext in [".pdf", ".docx", ".xlsx", ".pptx", ".txt", ".csv", ".json", ".xml"] else ("image" if ext in [".png", ".jpg"] else ("media" if ext in [".mp3", ".mp4"] else "archive")),
            "label": "CLEAN"
        })

    # 2. Generate SUSPICIOUS records
    suspicious_exts = [".ps1", ".js", ".bat", ".cmd", ".vbs", ".docm", ".xlsm", ".py", ".sh", ".zip"]
    for _ in range(suspicious_count):
        ext = random.choice(suspicious_exts)
        size = int(np.random.lognormal(mean=8.5, sigma=1.5)) # 1KB to 200KB
        size = max(128, min(size, 5 * 1024 * 1024))
        entropy = round(np.random.normal(loc=5.8, scale=0.8), 4)
        entropy = max(3.5, min(7.3, entropy))
        
        filename_len = random.randint(10, 45)
        spec_chars = random.randint(1, 6)
        complexity = round(spec_chars / max(filename_len, 1), 4)

        is_script = 1 if ext in [".ps1", ".js", ".bat", ".cmd", ".vbs", ".py", ".sh"] else 0
        is_macro = 1 if ext in [".docm", ".xlsm"] else 0
        has_ps = 1 if ext == ".ps1" or (is_script and random.random() < 0.4) else 0
        has_js = 1 if ext == ".js" or random.random() < 0.2 else 0

        records.append({
            "file_size": size,
            "file_entropy": entropy,
            "mime_mismatch": 1 if random.random() < 0.15 else 0,
            "filename_length": filename_len,
            "filename_complexity": complexity,
            "special_char_count": spec_chars,
            "is_hidden": 1 if random.random() < 0.10 else 0,
            "is_executable_ext": 0,
            "is_script_ext": is_script,
            "is_macro_ext": is_macro,
            "is_archive_ext": 1 if ext == ".zip" else 0,
            "has_double_extension": 0,
            "is_dangerous_extension": 1 if is_script else 0,
            "suspicious_string_count": random.randint(1, 4),
            "suspicious_url_count": random.randint(0, 3),
            "suspicious_cmd_count": random.randint(0, 2),
            "powershell_indicator": has_ps,
            "javascript_indicator": has_js,
            "vba_macro_indicator": is_macro,
            "obfuscation_score": round(random.uniform(0.20, 0.60), 2),
            "encoded_content_indicator": 1 if random.random() < 0.45 else 0,
            "eval_indicator": 1 if random.random() < 0.35 else 0,
            "nested_archive_depth": 1 if ext == ".zip" and random.random() < 0.3 else 0,
            "archive_has_executable": 0,
            "archive_has_script": 1 if ext == ".zip" and random.random() < 0.4 else 0,
            "compression_ratio": round(random.uniform(1.2, 3.5), 2),
            "non_ascii_ratio": round(random.uniform(0.15, 0.55), 4),
            "magic_entropy": round(random.uniform(3.0, 6.0), 4),
            "magic_is_pe": 0,
            "extension_category": "script" if is_script else ("document" if is_macro else "archive"),
            "label": "SUSPICIOUS"
        })

    # 3. Generate MALICIOUS records
    malicious_exts = [".exe", ".dll", ".scr", ".pif", ".pdf.exe", ".doc.ps1", ".docx.exe", ".zip", ".bat", ".hta"]
    for _ in range(malicious_count):
        ext_choice = random.choice(malicious_exts)
        has_double = 1 if ".pdf.exe" in ext_choice or ".doc.ps1" in ext_choice or ".docx.exe" in ext_choice else 0
        is_exe = 1 if ".exe" in ext_choice or ".dll" in ext_choice or ".scr" in ext_choice else 0
        
        size = int(np.random.lognormal(mean=10.0, sigma=1.6))
        size = max(1024, min(size, 30 * 1024 * 1024))
        entropy = round(np.random.normal(loc=7.1, scale=0.6), 4)
        entropy = max(5.5, min(7.99, entropy))

        filename_len = random.randint(12, 55)
        spec_chars = random.randint(2, 9)
        complexity = round(spec_chars / max(filename_len, 1), 4)

        mime_mismatch = 1 if has_double or (random.random() < 0.40 and not is_exe) else (1 if random.random() < 0.3 else 0)

        records.append({
            "file_size": size,
            "file_entropy": entropy,
            "mime_mismatch": mime_mismatch,
            "filename_length": filename_len,
            "filename_complexity": complexity,
            "special_char_count": spec_chars,
            "is_hidden": 1 if random.random() < 0.25 else 0,
            "is_executable_ext": is_exe,
            "is_script_ext": 1 if ".ps1" in ext_choice or ".bat" in ext_choice or ".hta" in ext_choice else 0,
            "is_macro_ext": 0,
            "is_archive_ext": 1 if ".zip" in ext_choice else 0,
            "has_double_extension": has_double,
            "is_dangerous_extension": 1,
            "suspicious_string_count": random.randint(3, 15),
            "suspicious_url_count": random.randint(1, 7),
            "suspicious_cmd_count": random.randint(1, 6),
            "powershell_indicator": 1 if random.random() < 0.65 else 0,
            "javascript_indicator": 1 if random.random() < 0.40 else 0,
            "vba_macro_indicator": 1 if random.random() < 0.30 else 0,
            "obfuscation_score": round(random.uniform(0.50, 0.98), 2),
            "encoded_content_indicator": 1 if random.random() < 0.80 else 0,
            "eval_indicator": 1 if random.random() < 0.60 else 0,
            "nested_archive_depth": 2 if ".zip" in ext_choice and random.random() < 0.5 else 0,
            "archive_has_executable": 1 if ".zip" in ext_choice else 0,
            "archive_has_script": 1 if ".zip" in ext_choice and random.random() < 0.6 else 0,
            "compression_ratio": round(random.uniform(1.8, 5.0), 2),
            "non_ascii_ratio": round(random.uniform(0.35, 0.85), 4),
            "magic_entropy": round(random.uniform(4.5, 7.5), 4),
            "magic_is_pe": 1 if is_exe or random.random() < 0.5 else 0,
            "extension_category": "executable" if is_exe else ("script" if "ps1" in ext_choice or "bat" in ext_choice else "archive"),
            "label": "MALICIOUS"
        })

    # Shuffle dataset
    random.shuffle(records)
    df = pd.DataFrame(records)

    # Inject minor realistic noise for cleaning pipeline test:
    # 1. Duplicate rows (e.g. 50 duplicate rows)
    dup_rows = df.sample(n=50, random_state=42)
    df = pd.concat([df, dup_rows], ignore_index=True)

    # 2. Add some alternate labels that the cleaning pipeline normalizes (e.g. 'malware', 'benign')
    mask_benign = df["label"] == "CLEAN"
    benign_sample = df[mask_benign].sample(n=30, random_state=42).index
    df.loc[benign_sample, "label"] = "benign"

    mask_malware = df["label"] == "MALICIOUS"
    malware_sample = df[mask_malware].sample(n=25, random_state=42).index
    df.loc[malware_sample, "label"] = "malware"

    # Save to raw dataset path
    df.to_csv(output_path, index=False)
    print(f"Generated {len(df)} records in {output_path}")
    print(f"Class counts:\n{df['label'].value_counts()}")
    return output_path

if __name__ == "__main__":
    target = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "ml", "datasets", "raw", "security_dataset.csv")
    generate_security_dataset(target, total_records=12000)
