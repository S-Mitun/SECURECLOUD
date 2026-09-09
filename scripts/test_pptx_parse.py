import sys, os, sqlite3
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from backend.app.services.presentation_service import PresentationService

conn = sqlite3.connect('securecloud.db')
c = conn.cursor()
c.execute("SELECT id, filename, storage_path, file_size FROM files WHERE filename LIKE '%KNOWLWDGE%' OR filename LIKE '%pptx'")
rows = c.fetchall()
print("Found files matching PPTX:", len(rows))
for r in rows:
    print(r)
    if os.path.exists(r[2]):
        print(f"File exists on disk: {r[2]} ({os.path.getsize(r[2])} bytes)")
        with open(r[2], "rb") as fp:
            raw = fp.read()
        res = PresentationService.render_presentation(raw, "testhash", r[1])
        print("Format:", res.get("format"), "| Slide count:", res.get("slide_count"))
        if res.get("slides"):
            print("First slide title:", res["slides"][0].get("title"), "| Elements in slide 1:", len(res["slides"][0].get("elements", [])))
