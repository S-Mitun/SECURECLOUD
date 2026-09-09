with open("backend/app/api/soc.py", "r", encoding="utf-8") as f:
    text = f.read()

text = text.replace(
    'def get_policy_execution_history(\n    policy_id: int,',
    'def get_policy_execution_history(\n    policy_id: str,'
)

text = text.replace(
    'def trigger_policy_manual_execution(\n    policy_id: int,',
    'def trigger_policy_manual_execution(\n    policy_id: str,'
)

with open("backend/app/api/soc.py", "w", encoding="utf-8") as f:
    f.write(text)

print("[OK] Updated policy_id to str in soc.py!")
