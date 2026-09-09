with open("backend/app/api/soc.py", "r", encoding="utf-8") as f:
    text = f.read()

text = text.replace(
    "from fastapi import APIRouter, Depends, HTTPException, status, Query, Request, Body",
    "from fastapi import APIRouter, Depends, HTTPException, status, Query, Request, Body, Form, File, UploadFile"
)

with open("backend/app/api/soc.py", "w", encoding="utf-8") as f:
    f.write(text)

print("[OK] Updated soc.py with Form, File, UploadFile imports!")
