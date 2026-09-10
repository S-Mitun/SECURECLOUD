# 🛡️ SecureCloud
> **"Secure Storage. Intelligent Protection."**  
> Enterprise Zero-Trust Cloud Storage, Real-Time AI Threat Classification & Security Operations Center (SOC) Platform

---

[![Live Demo](https://img.shields.io/badge/Live%20Demo-Railway%20Cloud-00C7B7?style=for-the-badge&logo=railway&logoColor=white)](https://securecloud-app-production.up.railway.app)
[![System Status](https://img.shields.io/badge/System%20Status-Healthy%20%7C%20Online-10B981?style=for-the-badge)](https://securecloud-app-production.up.railway.app/health)
[![Backend](https://img.shields.io/badge/Backend-FastAPI%20v0.110-009688?style=for-the-badge&logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com)
[![Frontend](https://img.shields.io/badge/Frontend-React%2018%20%7C%20Vite-61DAFB?style=for-the-badge&logo=react&logoColor=black)](https://react.dev)
[![AI Engine](https://img.shields.io/badge/AI%20Threat%20Model-LightGBM%20%2B%20EMBER-FF6F00?style=for-the-badge&logo=scikitlearn&logoColor=white)](https://lightgbm.readthedocs.io)
[![Encryption](https://img.shields.io/badge/Cryptography-AES--256--GCM-4F46E5?style=for-the-badge&logo=shield&logoColor=white)](https://github.com/S-Mitun/SECURECLOUD)

---

## 🌐 Live Cloud Deployment

SecureCloud is deployed live as a unified, production-grade container on Railway Cloud. Everyone can access and evaluate both the **User Vault Portal** and the **Admin SOC Portal** using the live demo link below:

### 🔗 **[Launch SecureCloud Live Application](https://securecloud-app-production.up.railway.app)**

> **Production Gateway:** `https://securecloud-app-production.up.railway.app`  
> **API Health Probe:** `https://securecloud-app-production.up.railway.app/health`  
> **Swagger API Documentation:** `https://securecloud-app-production.up.railway.app/docs`

---

### 🔑 Pre-Configured Demo Credentials

The platform enforces strict server-side role isolation. Users can only log into their designated portal:

| Portal Type | URL / Mode | Email / Username | Password | Dual-Auth Security Code | Permissions & Scope |
|---|---|---|---|---|---|
| **User Vault Portal** | [Access User Portal](https://securecloud-app-production.up.railway.app) | `Rahul` | `Rahul@123` | *N/A (Standard OTP)* | File Upload, Zero-Knowledge Vault, File Sharing, Soft Delete, Multi-Format Previews |
| **Admin SOC Portal** | [Access Admin Portal](https://securecloud-app-production.up.railway.app) | `Remo` | `Remo@123` | `994422` | Full SOC Operations, Ingestion Audit, Threat Correlation, Sentinel VM, Quarantine, IP Guard |

*(You can also register new user accounts directly through the registration tab in the User portal!)*

---

## 🏛️ System Architecture

SecureCloud is engineered with a modular, zero-trust architecture separating user-space storage from administrative threat telemetry:

```
                                  [ INTERNET / CLIENT INGRESS ]
                                                │
                                  ┌─────────────┴─────────────┐
                                  │   Railway Cloud Ingress   │
                                  │   (HTTPS / TLS 1.3 Term)  │
                                  └─────────────┬─────────────┘
                                                │
                 ┌──────────────────────────────┴──────────────────────────────┐
                 │                                                             │
      [ React 18 + Vite SPA ]                                      [ FastAPI ASGI Gateway ]
      ├─ Cyber Dark SOC Theme                                      ├─ Strict Role-Based Access Control
      ├─ Canvas 2D Telemetry Waveforms                             ├─ Session-Bound JWT Auth + Dual-Admin Gate
      ├─ Format-Preserving Document Viewers                        ├─ RESTful API Engine
      └─ Web Audio Military Alarm Siren                            └─ Prometheus Metrics (/metrics)
                 │                                                             │
                 └──────────────────────────────┬──────────────────────────────┘
                                                │
                 ┌──────────────────────────────┴──────────────────────────────┐
                 │                                                             │
     [ Storage & Enclave Layer ]                                   [ Threat Intelligence Core ]
     ├─ Active Uploads (UUID Isolation)                            ├─ 30+ Static Heuristic Extractor
     ├─ Zero-Knowledge Vault (AES-256-GCM)                         ├─ Shannon Entropy Analysis (0.0 - 8.0)
     ├─ Progressive Lockout Shield (State Engine)                  ├─ LightGBM / EMBER ML Inference Engine
     ├─ Soft-Delete Recycle Bin (IST Timestamps)                   ├─ Real-Time Signal Fusion & Health Scoring
     └─ Quarantine Staging Vault                                   └─ Event-Driven SOC Correlation Engine
```

---

## 🛠️ Complete Technology Stack

SecureCloud uses a carefully curated stack to provide security, speed, and real-time intelligence:

### Frontend
- **Framework & Runtime**: React 18 (`react`, `react-dom`, `react-router-dom` v6)
- **Build Tool**: Vite 5 with Hot Module Replacement & production chunk optimization
- **Styling**: Vanilla CSS & Tailwind CSS dark theme design system
- **Icons**: Lucide React (`lucide-react`)
- **Telemetry Visualizer**: HTML5 Canvas 2D API for continuous harmonic telemetry waveforms
- **Acoustic Defense**: HTML5 Web Audio API synthesizing military base breach sirens client-side without external media assets

### Backend & Security
- **Web Engine**: FastAPI (ASGI) on Uvicorn with asynchronous worker threading
- **Validation**: Pydantic v2 schemas for request/response serialization
- **Database ORM**: SQLAlchemy 2.0 with connection pooling and automated schema management
- **Database Engine**: SQLite (embedded production-synced) / PostgreSQL (`psycopg2-binary`)
- **Authentication**: JWT (`pyjwt`), Bcrypt (`bcrypt`), and Dual-Admin Authorization Keys
- **Zero-Knowledge Cryptography**: `cryptography` (AES-256-GCM with authenticated tags, PBKDF2-HMAC-SHA256 key derivation with 100,000 iterations)
- **System Monitoring**: `psutil` (real-time CPU, RAM, and disk telemetry)

### Machine Learning & Static Heuristics
- **Inference Model**: LightGBM (`lightgbm>=4.3.0`) trained on PE/static heuristic feature sets
- **Pipelines**: Scikit-learn (`scikit-learn>=1.4.0`), Joblib (`joblib`)
- **Data Math**: NumPy (`numpy`), Pandas (`pandas`)
- **Static Feature Extractor**: 30+ structural metrics including Shannon entropy, magic byte verification, MIME validation, double extension traps, encoded script signatures, and macro heuristics

### Document Parsers & Viewers
- **DOCX**: `python-docx` and `mammoth` (HTML paragraph and table extraction)
- **XLSX**: `openpyxl` (multisheet spreadsheet grid extraction)
- **PPTX**: `python-pptx` (slide-by-slide structure extraction)
- **PDF & Images**: `Pillow`, `reportlab`, `fpdf2`, native PDF streaming
- **Source Code & Binary**: Safe syntax highlight and raw hexadecimal byte inspector

---

## ⚡ Key Capabilities & Security Controls

### 1. Format-Preserving, Byte-Exact File Viewer
- **Zero Byte Distortion**: The original bytes are stored strictly unmodified. Downloads verify identical SHA-256 hashes (`HASH_PRE == HASH_POST`).
- **Rich Document Rendering**: True structured previews for `.docx`, `.xlsx`, `.pptx`, `.pdf`, code files (`.py`, `.js`, `.json`, `.html`, etc.), images, audio, video, and safe binary hex inspect.

### 2. Zero-Knowledge Confidential Vault with Progressive Lockout
- **Client/PIN Encryption**: Files are encrypted with AES-256-GCM. System administrators cannot access or decrypt raw content without the user's secret PIN.
- **Stateful Exponential Lockout**: Protects against brute-force attacks. Failed attempts trigger timed lockouts (e.g., 30 minutes, 2 hours) with an active countdown timer.
- **Resilient Countdown Engine**: Standardized ISO 8601 UTC timestamps prevent client-side parsing failures and ensure accurate countdown display.

### 3. Secure Soft-Delete Recycle Bin with Accurate IST Timestamps
- **Isolated Staging**: Soft-deleted files are isolated in the Recycle Bin and cannot be executed or previewed until restored.
- **Indian Standard Time (IST)**: All deletion events are formatted into readable IST timestamps (e.g., `09 Sep 2026, 02:34:07 PM IST`), with dual backend formatting and client-side locale validation.

### 4. Admin Multi-User Ingestion Hub & Intrinsic Health Scores
- **Admin Ingestion Telemetry**: Admins can stage and ingest files into specific user vaults with full cryptographic audit trails.
- **Intrinsic Health Scoring**: Files with low ML threat probability display an accurate **Intrinsic Health Score** (e.g., a file with a `4.5%` threat score displays an intrinsic health score of `95.5%`), providing clear risk transparency.

### 5. SOC Threat Intelligence & Correlation Engine
- **Event-Driven Correlation**: Deterministically correlates IOCs, anomalous login attempts, brute-force patterns, and payload signatures without random numbers.
- **4 Actionable SOC Remediation Policies**:
  1. **Ingress Firewall Defense**: Blacklists offending IP addresses in the SOC Firewall.
  2. **Cryptographic Sandbox Isolation**: Quarantines high-risk payload hashes into the AES-256 Quarantine Vault.
  3. **Identity & Access Management (IAM)**: Enforces mandatory Two-Factor Authentication (2FA) on target accounts.
  4. **Session & Distribution Broker**: Revokes exposed public distribution share tokens and isolates session perimeters.
- **Full Containment**: Executing countermeasure vectors systematically reduces the incident threat score down to `0.0% (Clean)`, automatically updating linked incident records and audit logs.

### 6. Interactive Sentinel VM Security Console
- **Fluid Telemetry Waveforms**: Real-time canvas waveform animations generated using continuous trigonometric harmonic functions without artificial random jitter.
- **Military Breach Alarm**: Includes a synthetic base breach siren powered by the Web Audio API with volume and mute controls.

### 7. Strict Multi-Tenant Portal Isolation
- **Role Enforcement**: Server-side verification ensures user credentials cannot authenticate to the admin portal, and admin accounts cannot log into the user portal, preventing horizontal and vertical privilege escalation.

---

## 📁 Repository Directory Structure

```
SECURECLOUD/
├── backend/
│   ├── app/
│   │   ├── api/
│   │   │   ├── auth.py             # User & Admin authentication, 2FA TOTP, session validation
│   │   │   ├── files.py            # Uploads, streaming download, previewers, renaming, versioning
│   │   │   ├── confidential.py     # AES-256-GCM Zero-Knowledge Vault & Progressive Lockout
│   │   │   ├── recycle_bin.py      # Soft-delete staging, restoration, IST time formatting
│   │   │   ├── shares.py           # Expiring distribution share links
│   │   │   ├── soc.py              # SOC Dashboard, Ingestion Hub, Trust Registry, Telemetry
│   │   │   └── notifications.py    # Security alerts and user activity feeds
│   │   ├── models/                 # SQLAlchemy database models (14+ relational tables)
│   │   ├── schemas/                # Pydantic data validation schemas
│   │   ├── security/               # AES-GCM cryptography, Bcrypt hashing, JWT handlers
│   │   ├── services/               # Threat Intel Service, Risk Engine, Audit Logger, Storage Service
│   │   ├── database.py             # Engine initialization, session makers
│   │   └── main.py                 # FastAPI application definition and middleware
│   ├── requirements.txt            # Python production dependencies
│   └── run.py                      # Production startup entrypoint
├── frontend/
│   ├── src/
│   │   ├── api/                    # Centralized resilient API clients (authApi, fileApi, adminApi)
│   │   ├── components/             # Reusable UI components:
│   │   │   ├── FileViewerModal.jsx # DOCX, XLSX, PPTX, PDF, Code, Video, Audio, Hex viewers
│   │   │   ├── PinUnlockModal.jsx  # Zero-knowledge PIN entry with lockout integration
│   │   │   ├── LockoutCountdown.jsx# Multi-strategy timer parser
│   │   │   ├── AdminIngestionModal.jsx # Ingestion vector audit & Intrinsic Health scores
│   │   │   ├── SecurityDetailsModal.jsx# Static heuristics, ML threat probabilities & health
│   │   │   └── Navbar.jsx          # Role-aware responsive navigation header
│   │   ├── pages/                  # Application views:
│   │   │   ├── Login.jsx           # Portal selector, Captcha, Dual-Auth Key recovery
│   │   │   ├── MyFiles.jsx         # User file manager, upload drops, threat badges
│   │   │   ├── ConfidentialVault.jsx # Encrypted zero-knowledge vault
│   │   │   ├── RecycleBin.jsx      # Soft-delete staging with IST timestamps
│   │   │   ├── SharedLinks.jsx     # Active distribution shares
│   │   │   ├── PasswordSaves.jsx   # Client-side vault key history
│   │   │   ├── UserActivity.jsx    # User audit log feed
│   │   │   └── admin/              # SOC views (Dashboard, Ingestion, Threat Correlation, Sentinel VM, etc.)
│   │   ├── context/                # AppContext (modals, audio, toasts), AuthContext
│   │   ├── App.jsx                 # Route definitions and role guards
│   │   └── main.jsx                # React DOM root mounting
│   ├── package.json                # Frontend scripts and dependencies
│   └── vite.config.js              # Vite bundler configuration
├── ml/
│   ├── feature_extractor.py        # 30+ static parameter and Shannon entropy extractor
│   ├── predict.py                  # LightGBM inference engine
│   └── trained_models/             # Persisted ML model weights
├── storage/                        # Isolated file system vaults
│   ├── uploads/                    # Active user storage (UUID namespaced)
│   ├── confidential/               # PIN-encrypted AES-256-GCM blobs
│   ├── quarantine/                 # Quarantined threat files
│   └── recycle_bin/                # Staged soft-deleted files
├── Dockerfile                      # Production multi-stage Docker build
├── railway.json                    # Railway deployment manifest
└── README.md                       # Comprehensive system documentation
```

---

## 🚀 Local Installation & Setup

### Prerequisites
- **Python**: Version 3.10, 3.11, or 3.12
- **Node.js**: Version 18+ and npm
- **Git**

### 1. Clone the Repository
```bash
git clone https://github.com/S-Mitun/SECURECLOUD.git
cd SECURECLOUD
```

### 2. Set Up Python Backend
```bash
# Create and activate a virtual environment
python -m venv venv

# On Windows:
.\venv\Scripts\activate
# On Linux/macOS:
source venv/bin/activate

# Install dependencies
pip install -r backend/requirements.txt
```

### 3. Set Up React Frontend
```bash
cd frontend
npm install
cd ..
```

### 4. Run Locally

#### Option A: Quickstart Script (Windows)
```powershell
.\start_securecloud.ps1
```

#### Option B: Manual Two-Terminal Run
**Terminal 1 — Backend:**
```bash
python -m uvicorn backend.app.main:app --host 127.0.0.1 --port 8000 --reload
```

**Terminal 2 — Frontend:**
```bash
cd frontend
npm run dev
```

The frontend will start at `http://localhost:5173` and communicate with the backend at `http://127.0.0.1:8000`.

---

## 🧪 Testing & Automated Verification

SecureCloud includes automated test suites covering authentication, role isolation, ML threat scoring, and IST time conversions:

```bash
# Run acceptance test suite
python scripts/test_acceptance.py

# Verify role isolation and portal boundaries
python scratch/verify_prod_portal_isolation.py
```

---

## 📜 API Reference Highlights

| Method | Endpoint | Access | Description |
|---|---|---|---|
| `POST` | `/api/auth/login` | Public | Multi-portal login with role enforcement and mock captcha |
| `POST` | `/api/auth/register` | Public | New user registration |
| `GET` | `/api/files/list` | User | Lists active files with calculated ML threat scores |
| `POST` | `/api/files/upload` | User | Uploads and scans file with 30+ static heuristics & ML |
| `GET` | `/api/confidential/list` | User | Lists client-encrypted files in Zero-Knowledge Vault |
| `POST` | `/api/confidential/unlock` | User | Validates PIN and returns decrypted content for viewing |
| `GET` | `/api/recycle-bin/list` | User | Lists soft-deleted files with formatted IST timestamps |
| `POST` | `/api/recycle-bin/{id}/restore`| User | Restores file from Recycle Bin back to active workspace |
| `GET` | `/api/soc/dashboard` | Admin | Overall SOC telemetry, breach stats, and file metrics |
| `GET` | `/api/soc/files/{id}/security-details` | Admin | Returns genuine ML threat scores and Intrinsic Health scores |
| `GET` | `/api/soc/threat-intelligence/correlation` | Admin | Deterministic IOC correlation clusters |
| `POST` | `/api/soc/threat-intelligence/mitigate-cluster`| Admin | Executes targeted SOC countermeasures (Firewall, Sandbox, 2FA, Shares) |
| `GET` | `/health` | Public | Liveness probe for deployment health checks |

---

## 🔒 Security Notice

SecureCloud inspects files using static feature extraction, heuristic pattern matching, and machine learning inference. Uploaded files are analyzed in a sandboxed staging process without executing untrusted binaries. Client-side confidential documents are encrypted using AES-256-GCM, ensuring that even administrative accounts cannot view zero-knowledge vault contents.

---

## 👨‍💻 Author & Maintainer
- **Mitun S** — [GitHub: @S-Mitun](https://github.com/S-Mitun)  
- **Repository**: [https://github.com/S-Mitun/SECURECLOUD](https://github.com/S-Mitun/SECURECLOUD)
