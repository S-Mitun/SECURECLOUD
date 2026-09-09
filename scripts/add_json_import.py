with open("backend/app/api/soc.py", "r", encoding="utf-8") as f:
    text = f.read()

if "import json" not in text:
    text = "import json\n" + text
    with open("backend/app/api/soc.py", "w", encoding="utf-8") as f:
        f.write(text)
    print("[OK] Added import json to top of soc.py!")
else:
    print("[OK] import json already present in soc.py")
