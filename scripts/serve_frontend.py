"""
SecureCloud 2.0 - Static Frontend Server
Serves the HTML/CSS/JS frontend cleanly on port 5500 with proper MIME types and CORS headers.
"""

import os
import sys
from pathlib import Path
from http.server import HTTPServer, SimpleHTTPRequestHandler

ROOT_DIR = Path(__file__).resolve().parent.parent
FRONTEND_DIR = ROOT_DIR / "frontend"

class SecureCloudFrontendHandler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(FRONTEND_DIR), **kwargs)

    def end_headers(self):
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, HEAD, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "*")
        self.send_header("Cache-Control", "no-cache, no-store, must-revalidate")
        super().end_headers()

    def do_OPTIONS(self):
        self.send_response(200)
        self.end_headers()

    def log_message(self, format, *args):
        # Concise logging
        sys.stderr.write(f"[Frontend Server] {self.address_string()} - {format % args}\n")

def run_server(port: int = 5500, host: str = "127.0.0.1"):
    server_address = (host, port)
    httpd = HTTPServer(server_address, SecureCloudFrontendHandler)
    print(f"SecureCloud 2.0 Frontend Server running on http://{host}:{port} (Serving: {FRONTEND_DIR})")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down Frontend Server...")
        httpd.server_close()

if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 5500
    host = sys.argv[2] if len(sys.argv) > 2 else "127.0.0.1"
    run_server(port=port, host=host)
