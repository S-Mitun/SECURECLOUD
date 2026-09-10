"""
SecureCloud - Server Runner
"""

import uvicorn
import os
import sys

# Ensure parent directory is in sys.path
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

if __name__ == "__main__":
    port = int(os.getenv("PORT", 8000))
    is_prod = os.getenv("ENVIRONMENT") == "production" or bool(os.getenv("RAILWAY_ENVIRONMENT"))
    # In cloud containers (like Railway), bind to 0.0.0.0 so external proxy can connect
    default_host = "0.0.0.0" if (is_prod or os.getenv("PORT")) else "127.0.0.1"
    host = os.getenv("HOST", default_host)
    
    print(f"Starting SecureCloud on http://{host}:{port} (production={is_prod})")
    uvicorn.run(
        "backend.app.main:app",
        host=host,
        port=port,
        reload=not is_prod,
        reload_dirs=[os.path.join(BASE_DIR, "backend")] if not is_prod else None
    )
