with open("backend/app/api/soc.py", "r", encoding="utf-8") as f:
    text = f.read()

text = text.replace(
    "scan_result = predictor.predict(raw_bytes, clean_filename)",
    "scan_result = predictor.predict_file(raw_bytes, clean_filename)"
)

with open("backend/app/api/soc.py", "w", encoding="utf-8") as f:
    f.write(text)

print("[OK] Fixed predictor.predict_file in soc.py!")
