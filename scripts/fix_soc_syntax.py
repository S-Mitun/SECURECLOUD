with open("backend/app/api/soc.py", "r", encoding="utf-8") as f:
    text = f.read()

text = text.replace(
    """        "message": f"Policy '{policy.name}' executed successfully (Run #{policy.execution_count})."
    }."
}""",
    """        "message": f"Policy '{policy.name}' executed successfully (Run #{policy.execution_count})."
    }"""
)

with open("backend/app/api/soc.py", "w", encoding="utf-8") as f:
    f.write(text)

print("[OK] Fixed syntax in soc.py!")
