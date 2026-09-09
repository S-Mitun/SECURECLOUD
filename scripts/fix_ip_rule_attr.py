with open("backend/app/api/soc.py", "r", encoding="utf-8") as f:
    text = f.read()

old_ip_inst = """            rule = IPRule(
                ip_address=ip,
                rule_type="BLACKLIST",
                reason=f"Automated Mitigation {cluster_id}: {action_text}",
                is_active=True,
                created_by=current_admin.username,
                created_at=datetime.utcnow()
            )"""

new_ip_inst = """            rule = IPRule(
                ip_address=ip,
                rule_type="BLACKLIST",
                description=f"Automated Mitigation {cluster_id}: {action_text}",
                threat_status="CRITICAL_BLOCKED",
                is_active=True
            )"""

text = text.replace(old_ip_inst, new_ip_inst)

with open("backend/app/api/soc.py", "w", encoding="utf-8") as f:
    f.write(text)

print("[OK] Fixed IPRule attributes in soc.py!")
