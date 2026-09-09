with open("backend/app/api/soc.py", "r", encoding="utf-8") as f:
    text = f.read()

text = text.replace('type="SECURITY_WARNING"', 'severity="WARNING"')
text = text.replace('type="SECURITY_INFO"', 'severity="INFO"')

with open("backend/app/api/soc.py", "w", encoding="utf-8") as f:
    f.write(text)

print("[OK] Fixed Notification severity field in backend/app/api/soc.py!")
