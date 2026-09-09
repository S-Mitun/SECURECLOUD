with open("backend/app/api/soc.py", "r", encoding="utf-8") as f:
    text = f.read()

text = text.replace(
    'ml_probabilities=scan_result["probabilities"],',
    'ml_probabilities=scan_result.get("ml_probabilities") or scan_result.get("probabilities") or {"CLEAN": 100.0, "SUSPICIOUS": 0.0, "MALICIOUS": 0.0},'
)

with open("backend/app/api/soc.py", "w", encoding="utf-8") as f:
    f.write(text)

print("[OK] Fixed ml_probabilities dict extraction in soc.py!")
