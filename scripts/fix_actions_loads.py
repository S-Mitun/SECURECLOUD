with open("backend/app/api/soc.py", "r", encoding="utf-8") as f:
    text = f.read()

old_actions_loads = 'actions_list = json.loads(policy.actions) if policy.actions else ["QUARANTINE_FILES"]'
new_actions_loads = 'actions_list = policy.actions if isinstance(policy.actions, list) else (json.loads(policy.actions) if isinstance(policy.actions, str) else ["QUARANTINE_FILES"])'

text = text.replace(old_actions_loads, new_actions_loads)

with open("backend/app/api/soc.py", "w", encoding="utf-8") as f:
    f.write(text)

print("[OK] Fixed policy.actions parsing in soc.py!")
