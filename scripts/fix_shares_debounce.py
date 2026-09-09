# 1. Update PublicShareView.jsx
with open("frontend/src/pages/PublicShareView.jsx", "r", encoding="utf-8") as f:
    ps_text = f.read()

if "useRef" not in ps_text:
    ps_text = ps_text.replace(
        "import React, { useState, useEffect } from 'react';",
        "import React, { useState, useEffect, useRef } from 'react';"
    )

if "const fetchedRef = useRef" not in ps_text:
    ps_text = ps_text.replace(
        "export function PublicShareView() {",
        "export function PublicShareView() {\n  const fetchedRef = useRef(false);"
    )

    ps_text = ps_text.replace(
        "useEffect(() => {\n    loadShare();\n  }, [id]);",
        "useEffect(() => {\n    if (fetchedRef.current) return;\n    fetchedRef.current = true;\n    loadShare();\n  }, [id]);"
    )

with open("frontend/src/pages/PublicShareView.jsx", "w", encoding="utf-8") as f:
    f.write(ps_text)
print("[OK] Updated PublicShareView.jsx to prevent double mount fetch!")

# 2. Update backend/app/api/shares.py with IP debounce
with open("backend/app/api/shares.py", "r", encoding="utf-8") as f:
    sh_text = f.read()

debounce_cache_code = """
# In-memory debounce cache to prevent duplicate view increments (IP + ShareID within 5 seconds)
_VIEW_DEBOUNCE_CACHE = {}
"""

if "_VIEW_DEBOUNCE_CACHE" not in sh_text:
    sh_text = debounce_cache_code + "\n" + sh_text

# Update get_public_share_info increment logic
old_inc_logic = """    share.view_count += 1
    db.commit()"""

new_inc_logic = """    # 5-second per-IP debounce to prevent double-counting
    client_ip = request.client.host if request.client else "unknown"
    cache_key = f"{share.id}_{client_ip}"
    now_ts = datetime.utcnow().timestamp()
    
    if cache_key not in _VIEW_DEBOUNCE_CACHE or (now_ts - _VIEW_DEBOUNCE_CACHE[cache_key]) > 5.0:
        share.view_count += 1
        db.commit()
        _VIEW_DEBOUNCE_CACHE[cache_key] = now_ts"""

if "client_ip = request.client.host" not in sh_text:
    sh_text = sh_text.replace(
        "def get_public_share_info(\n    share_id: str,\n    db: Session = Depends(get_db)\n):",
        "def get_public_share_info(\n    share_id: str,\n    request: Request,\n    db: Session = Depends(get_db)\n):"
    )
    sh_text = sh_text.replace(old_inc_logic, new_inc_logic)

with open("backend/app/api/shares.py", "w", encoding="utf-8") as f:
    f.write(sh_text)
print("[OK] Updated shares.py with 5-second debounce!")
