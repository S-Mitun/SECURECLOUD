with open("backend/app/api/soc.py", "r", encoding="utf-8") as f:
    lines = f.readlines()

# Replace line 2024 and 2025 with just '    }'
for i in range(len(lines)):
    if '    }."' in lines[i]:
        lines[i] = "    }\n"
        if i + 1 < len(lines) and lines[i+1].strip() == "}":
            lines[i+1] = "\n"

with open("backend/app/api/soc.py", "w", encoding="utf-8") as f:
    f.writelines(lines)

print("[OK] Replaced lines cleanly in soc.py!")
