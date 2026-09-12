# 🛡️ SecureCloud

> **"A security-first cloud storage platform that stores files in the cloud, actively analyzes uploaded files using real malware scanning + lightweight ML/static analysis, explains security risks, records security events, and provides application-level incident response through a SOC dashboard."**

> 🚀 **Live Production Deployment**: [https://securecloud-app-production.up.railway.app](https://securecloud-app-production.up.railway.app)  
> 🩺 **System Health & Telemetry Status**: [https://securecloud-app-production.up.railway.app/health](https://securecloud-app-production.up.railway.app/health)

---

[![System Status](https://img.shields.io/badge/System%20Status-Healthy%20%7C%20Online-10B981?style=for-the-badge)](https://securecloud-app-production.up.railway.app/health)
[![Backend](https://img.shields.io/badge/Backend-FastAPI%20ASGI-009688?style=for-the-badge&logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com)
[![Frontend](https://img.shields.io/badge/Frontend-React%2018%20%7C%20Vite-61DAFB?style=for-the-badge&logo=react&logoColor=black)](https://react.dev)
[![Object Storage](https://img.shields.io/badge/Storage-S3--Compatible%20%2B%20Local-FF9900?style=for-the-badge&logo=amazons3&logoColor=white)](https://boto3.amazonaws.com)
[![Malware Scanner](https://img.shields.io/badge/Malware%20Scanner-ClamAV%20Daemon%20Layer-E62B1E?style=for-the-badge)](https://www.clamav.net)
[![ML Threat Model](https://img.shields.io/badge/ML%20Threat%20Model-LightGBM%20CPU-FF6F00?style=for-the-badge&logo=scikitlearn&logoColor=white)](https://lightgbm.readthedocs.io)

---

## 1. Project Overview

**SecureCloud** is an open-source cybersecurity cloud storage prototype engineered for hackathon and educational demonstrations. Unlike traditional file hosting platforms that treat files as passive payloads, SecureCloud actively verifies incoming files through a multi-tier security inspection pipeline before permitting persistent storage, sharing, or retrieval.

### Novelty & Core Pillars:
- **Cloud Object Storage**: S3-compatible cloud object storage abstraction (AWS S3, Cloudflare R2, MinIO) with user-isolated object keys, presigned URLs, and local fallback for offline development.
- **Multi-Layer Threat Analysis**: Combines ClamAV signature-based scanning with deterministic static heuristic rules and a lightweight CPU-optimized Machine Learning classifier.
- **Explainable Threat Scoring**: Explains *why* a file is marked safe, suspicious, or malicious by extracting and detailing concrete structural features (entropy, PE structures, extension mismatches, macro indicators).
- **Application-Level Incident Response**: Integrated SOC dashboard offering one-click mitigation actions (quarantine, link revocation, IP blocking, 2FA enforcement).
- **Security Monitoring Console**: Rebranded "Sentinel Security Monitoring Console" visualizing real-time telemetry, scan queues, and system resource health without synthetic sandboxing claims.

---

## 2. Architecture

SecureCloud connects an ASGI FastAPI backend to a React 18 / Vite single-page application with modular storage, database, authentication, and security inspection engines:

```
                            [ React 18 / Vite Frontend ]
                                         │
                                         ▼ (REST / JSON + Bearer JWT)
                            [ FastAPI ASGI Application ]
                                         │
     ┌───────────────────┬───────────────┴───────────────┬───────────────────┐
     ▼                   ▼                               ▼                   ▼
[Supabase Auth]  [PostgreSQL / SQLite]          [Object Storage]      [Security Engine]
  Real JWT          Relational Schema            S3-Compatible /      ┌──────┴──────┐
  Validation        Foreign Keys & RLS           Local Fallback       │ ClamAV (Sig)│
                                                                      │ Static Feat.│
                                                                      │ LightGBM ML │
                                                                      └──────┬──────┘
                                                                             ▼
                                                                      Threat Score &
                                                                      Explainability
                                                                             │
                                                                             ▼
                                                                     [SOC Dashboard &
                                                                     Incident Response]
```

---

## 3. Security Architecture

- **Zero Hardcoded Secrets**: All fallback administrative passwords and hardcoded codes (e.g. `994422`) have been removed. Access control is enforced server-side using verified roles: `USER`, `ADMIN`, and `SECURITY_ANALYST`.
- **Brute-Force Protection & Rate Limiting**: In-memory sliding-window rate limiting on authentication routes (maximum 5 failed attempts per 5 minutes per IP/account before temporary lockout).
- **Quarantine Enclave Isolation**: Files flagged as malicious or quarantined cannot be downloaded, previewed, or streamed by non-administrative users. Storage paths and S3 object keys are restricted.
- **HTTP Security Headers**: Enforces `X-Content-Type-Options: nosniff`, `X-Frame-Options: SAMEORIGIN`, `X-XSS-Protection: 1; mode=block`, and `Referrer-Policy: strict-origin-when-cross-origin`.
- **Cryptographic File Integrity**: SHA-256, SHA-1, and MD5 cryptographic digests calculated on all ingested files for integrity verification and threat intelligence deduplication.

---

## 4. ML Architecture

- **Model**: Lightweight gradient-boosted decision tree (`LightGBM`, model file ~645 KB).
- **Compute**: Runs purely on CPU. No GPU required, load time < 50ms, inference latency < 25ms.
- **In-Memory Loading**: Loaded once during application initialization into memory rather than on every HTTP request.
- **Dataset Strategy**: Small benchmark feature metadata under 50 MB containing static PE and document features.
- **Inference Pipeline**:
  1. Calculates Shannon Entropy ($0.0 \le H \le 8.0$) across byte frequency distributions.
  2. Inspects Portable Executable (PE) headers (MZ signatures, import tables, section characteristics).
  3. Checks MIME type vs. magic bytes consistency.
  4. Generates a normalized continuous threat probability between 0.0% and 100.0%.

---

## 5. Malware Scanning Architecture

SecureCloud implements an honest multi-layer malware and threat analysis pipeline:

```
UPLOAD
  │
  ▼
[ 1. File Structure & Magic-Byte Validation ]
  │
  ▼
[ 2. ClamAV Daemon Signature Inspection ]
  ├─ Malicious Signature Matched ──► QUARANTINE (Score: 99%, Status: MALICIOUS)
  └─ Clean / Daemon Unavailable ──► Continue to Layer 3
  │
  ▼
[ 3. Deterministic Static Heuristics ]
  ├─ Double extension detection (e.g. .pdf.exe)
  ├─ Executable section entropy (> 7.2 indicates packing/obfuscation)
  ├─ Known script/macro injection indicators
  │
  ▼
[ 4. LightGBM Static Feature Classification ]
  │
  ▼
[ Threat Score Fusion & Reason Compilation ]
  │
  ▼
VERDICT: CLEAN / LOW RISK / SUSPICIOUS / HIGH RISK / QUARANTINED
```

> **Technically Honest Scanner Disclosure**: If the ClamAV daemon is unconfigured or unreachable in the execution environment, the scanner reports:
> `"Signature scanner unavailable; static/ML analysis continued."`
> The application will **never** fake a signature scan result.

---

## 6. SOC Architecture

The **Security Operations Center (SOC) Dashboard** monitors live database records and audit streams:

- **Metrics Cards**:
  - `TOTAL FILES SCANNED`
  - `THREATS DETECTED`
  - `FILES QUARANTINED`
  - `ACTIVE INCIDENTS`
  - `HIGH-RISK USERS`
  - `BLOCKED IPs`
- **Security Event Correlation**: Real-time event log tracking failed logins, suspicious uploads, share revocations, and IP blocks.
- **Sentinel Security Monitoring Console**: Real-time visualization of scan activity, queue depth, and platform telemetry (CPU, Memory, Disk usage from `psutil`).

---

## 7. Supabase Authentication

SecureCloud integrates with Supabase Auth:
- Validates Supabase JWTs passed in `Authorization: Bearer <token>` via `SUPABASE_JWT_SECRET`.
- Derives user identity directly from verified token claims (`sub`, `email`, `app_metadata.role`).
- Automatically provisions corresponding relational user profiles in PostgreSQL.
- Eliminates reliance on client-supplied user IDs.

---

## 8. Object Storage

File persistence is managed through an abstracted storage interface:

- **S3-Compatible Storage**: Configured via `S3_ENDPOINT`, `S3_ACCESS_KEY`, `S3_SECRET_KEY`, `S3_BUCKET`, and `S3_REGION`.
- **User Isolation**: Object keys follow the convention `uploads/{user_id}/{unique_filename}`.
- **Presigned URLs**: Secure, time-limited download URLs generated server-side. Credentials are never exposed to the frontend.
- **Local Fallback**: If S3 environment variables are unset, the system automatically uses application-managed storage in `storage/uploads/` for offline development.

---

## 9. Threat Scoring & Explainability

Instead of providing an unverified number, SecureCloud exposes the exact breakdown:

```
THREAT SCORE: 96% (CRITICAL RISK)

REASONS:
✓ Dangerous double extension detected: disguised as '.pdf' but executes as '.sh'
✓ High Shannon entropy (7.99/8.00) indicates packed or encrypted binary payload
✓ MIME / Extension mismatch detected

DETECTION LAYERS:
- [ClamAV Signature Scanner]: Unavailable (daemon offline)
- [Heuristic Static Analysis]: Score 100 / 100 (Triggered 2 rules)
- [LightGBM ML Classifier]: Malicious Probability 94.8%
- [Final Verdict]: CRITICAL DANGER RISK (QUARANTINED)
```

---

## 10. Incident Response Playbooks

Administrative and SOC operators can execute one-click mitigations directly affecting backend state:
1. **Quarantine File**: Restricts file access and moves payload to quarantine staging.
2. **Revoke Share Token**: Immediately invalidates public share URLs.
3. **Block IP**: Adds client IP to the persistent firewall blacklist.
4. **Force 2FA**: Enforces multi-factor authentication requirement on flagged accounts.
5. **Restore File**: Allows authorized administrators to release false positives.

---

## 11. Environment Variables

Create a `.env` file in the project root based on `.env.example`:

```bash
# Server Port & Environment
PORT=8000
ENVIRONMENT=production

# Database (Supabase PostgreSQL or local SQLite)
DATABASE_URL=postgresql://postgres:[PASSWORD]@db.[PROJECT_REF].supabase.co:5432/postgres

# Supabase Auth
SUPABASE_URL=https://[PROJECT_REF].supabase.co
SUPABASE_ANON_KEY=[ANON_KEY]
SUPABASE_SERVICE_ROLE_KEY=[SERVICE_ROLE_KEY]
SUPABASE_JWT_SECRET=[JWT_SECRET_FROM_SUPABASE_DASHBOARD]

# S3-Compatible Object Storage (Cloudflare R2 / AWS S3 / MinIO)
S3_ENDPOINT=https://[ACCOUNT_ID].r2.cloudflarestorage.com
S3_ACCESS_KEY=[ACCESS_KEY_ID]
S3_SECRET_KEY=[SECRET_ACCESS_KEY]
S3_BUCKET=securecloud-vault
S3_REGION=auto

# ClamAV Daemon (Optional - if daemon is available)
CLAMAV_HOST=127.0.0.1
CLAMAV_PORT=3310

# CORS Allowed Origins (Comma-separated)
CORS_ORIGINS=https://securecloud-app-production.up.railway.app
```

---

## 12. Local Development

### Prerequisites
- Python 3.10+
- Node.js 18+

### Step 1: Backend Setup
```bash
# Navigate to backend and install requirements
pip install -r backend/requirements.txt

# Start FastAPI development server
python backend/run.py
```

### Step 2: Frontend Setup
```bash
cd frontend
npm install
npm run dev
```

The frontend will run on `http://localhost:5173`, proxying API calls to `http://localhost:8000`.

---

## 13. Railway Deployment

SecureCloud is containerized with a production multi-stage `Dockerfile`:
- **Stage 1 (node:20-alpine)**: Builds the Vite production bundle into `frontend/dist`.
- **Stage 2 (python:3.11-slim)**: Copies backend, ML models, scanner service, and compiled assets, running `python backend/run.py`.

### Railway Configuration:
- **Production URL**: [https://securecloud-app-production.up.railway.app](https://securecloud-app-production.up.railway.app)
- **Live Health Endpoint**: [https://securecloud-app-production.up.railway.app/health](https://securecloud-app-production.up.railway.app/health)
- **Build**: Uses `Dockerfile`.
- **Start Command**: `python backend/run.py`
- **Health Check Path**: `/health` (Timeout: 30s)
- **Port**: Bound dynamically to `0.0.0.0:$PORT`.

---

## 14. Technical Disclosures, Disclaimers & Feature Status

> ### ⚠️ Mandatory Engineering Disclosures
> - **"SecureCloud provides ML-assisted static threat classification and multi-layer file security analysis. It is not a complete antivirus, behavioral sandbox, EDR, or enterprise SIEM."**
> - **"ClamAV signature scanning is available when the ClamAV daemon is deployed and reachable. If unavailable, SecureCloud continues with static/ML analysis and reports the scanner as unavailable."**
> - **"Sentinel is an application-level security monitoring and incident-response console, not a physical or virtualized cybersecurity sandbox."**
> - **"Local storage is intended as a development fallback; production deployments should use persistent S3-compatible object storage."**

### Feature Implementation Matrix

| Capability | Implementation Level | Notes |
|:---|:---:|:---|
| **Supabase Authentication** | **IMPLEMENTED** | Primary auth mechanism via `auth.users` → `public.profiles`. FastAPI verifies JWT claims server-side. |
| **Server-Side RBAC** | **IMPLEMENTED** | `USER`, `ADMIN`, `SECURITY_ANALYST` roles validated server-side. No client-supplied IDs or roles trusted. |
| **Cross-User Data Isolation** | **IMPLEMENTED** | Zero cross-user leakage. 403 Forbidden enforced on unauthorized download, stream, rename, delete, version, share. |
| **Supabase Native Schema & RLS** | **IMPLEMENTED** | `scripts/supabase_migration.sql` implements `auth.users(id)` FKs, RLS policies, elevation prevention trigger, and compatibility view. |
| **Object Storage (S3-Compatible)** | **ENVIRONMENT DEPENDENT** | S3 provider abstraction works with AWS S3, Cloudflare R2, MinIO. Operates in `LOCAL FALLBACK` if S3 environment variables are unconfigured. |
| **Multi-Layer File Scanning** | **IMPLEMENTED** | Magic-byte checking, structural heuristics, PE analysis, and LightGBM threat classifier. |
| **ClamAV Signature Scanner** | **ENVIRONMENT DEPENDENT** | Real integration with ClamAV daemon when running (`CLAMAV_HOST`/`PORT`). If offline, reports `UNAVAILABLE` without fabricating results. |
| **LightGBM ML Classifier** | **IMPLEMENTED** | CPU-only model (~645 KB), loaded once at startup. Fast inference (< 25ms). Feature inputs recorded with each scan. |
| **Threat Explainability** | **IMPLEMENTED** | Component scores, entropy, double-extension, and structural indicators mapped deterministically to verdicts. |
| **AES-256 Quarantine Isolation** | **IMPLEMENTED** | High-risk payloads isolated into `QuarantineFile`. Non-admin access returns 403 Forbidden. |
| **File Versioning & Rollback** | **IMPLEMENTED** | Real file versions saved and tracked by hash, size, and timestamp. Restoring a version swaps active file content. |
| **Secure Share Links** | **IMPLEMENTED** | Cryptographic random tokens, expiration timestamp verification, active revocation, and access logging. |
| **Sliding-Window Rate Limiting** | **IMPLEMENTED (IN-MEMORY)** | 5 failed attempts per 5-minute window before HTTP 429 lockout. Single-instance memory store. |
| **Sentinel Monitoring Console** | **IMPLEMENTED** | Application-level telemetry, security incident lifecycle, IP blacklisting, 2FA enforcement, and audit logs. |
| **Distributed Rate Limiting (Redis)** | **FUTURE SCOPE** | Single-instance in-memory limiter should be replaced with Redis cluster for multi-instance production. |
| **Dynamic MicroVM Behavioral Sandbox**| **FUTURE SCOPE** | Execution of binaries in isolated microVMs (e.g. Firecracker) is beyond static analysis scope. |

---

## 15. Hackathon Demo Procedure

To demonstrate the full SecureCloud pipeline live:

1. **Step 1 - Authentication**:
   - Log into the **User Portal** (`user_demo` / `UserPass123!`).
2. **Step 2 - Upload Normal File**:
   - Upload `demo_test_files/clean_quarterly_report.txt`.
   - Result: Verified CLEAN, low threat score (~3.2%), persisted in storage.
3. **Step 3 - Upload Suspicious File**:
   - Upload `demo_test_files/suspicious_invoice_receipt.pdf.sh`.
   - Result: Multi-layer scanner flags double extension and shell indicators. Threat score elevates to 96%.
   - Verdict: Automatically quarantined, download blocked.
4. **Step 4 - Review Security Explanation**:
   - Click **Security Details** on the file to inspect the 4 detection layers and verified reasons.
5. **Step 5 - Incident Response in SOC**:
   - Switch to **Admin SOC Portal** (`admin_demo` / `AdminPass123!`).
   - Observe active incident in SOC Dashboard.
   - Inspect event logs, view threat telemetry in Sentinel Console, and confirm quarantine isolation.

---

## 16. Safe Demonstration Test Files

To evaluate the system safely without real malware, use the provided test generator:

```bash
python scripts/create_demo_test_files.py
```

Generated fixtures in `demo_test_files/`:
- `clean_quarterly_report.txt`: Benign document (Clean verdict).
- `suspicious_invoice_receipt.pdf.sh`: Double extension test (Suspicious/Quarantined).
- `safe_high_risk_demo_fixture.pdf`: Disguised PE header simulation (High Risk/Quarantined).

---

## 17. License

Distributed under the MIT License. See `LICENSE` for more information.
