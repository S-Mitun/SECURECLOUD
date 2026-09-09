import re

with open("backend/app/api/shares.py", "r", encoding="utf-8") as f:
    content = f.read()

# 1. Fix imports
content = content.replace(
    "from backend.app.services.storage_service import format_size",
    "from backend.app.services.storage_service import format_size, resolve_storage_path, sanitize_filename"
)

# 2. Add views_count to get_public_share_info
if '"views_count": share.view_count' not in content:
    content = content.replace(
        '"expires_at": share.expires_at.strftime("%Y-%m-%d %H:%M:%S") if share.expires_at else None,',
        '"expires_at": share.expires_at.strftime("%Y-%m-%d %H:%M:%S") if share.expires_at else None,\n        "views_count": share.view_count,\n        "view_count": share.view_count,'
    )

with open("backend/app/api/shares.py", "w", encoding="utf-8") as f:
    f.write(content)

print("[OK] Successfully patched backend/app/api/shares.py!")
