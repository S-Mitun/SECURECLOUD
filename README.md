# SECURECLOUD
> **"Secure Storage. Intelligent Protection."**
> Automated ML Threat Detection, Real-Time Heuristic Scanning & Security Intelligence Platform

---

## 1. Project Overview

**SecureCloud is a production-grade cloud storage and cybersecurity intelligence platform designed for zero-trust environments. Unlike conventional cloud vaults that rely solely on signature-based anti-virus or superficial checks, SecureCloud integrates a **genuine end-to-end Machine Learning training and inference pipeline** combined with **static heuristic scanning**, **cryptographic SHA-256 fingerprinting**, **zero-knowledge confidential vaults**, **format-preserving multi-type file previewers**, and **real-time SOC telemetry**.

---

## 2. Architecture & Pipeline

```
                                  [ USER / ADMIN ACCESS ]
                                             │
                       ┌─────────────────────┴─────────────────────┐
                       │                                           │
             [ Frontend Server ]                           [ FastAPI Backend ]
             (http://localhost:5500)                       (http://127.0.0.1:8000)
                       │                                           │
                       └─────────────────── CORS ──────────────────┘
                                             │
      ┌──────────────────────────────────────┼──────────────────────────────────────┐
      │                                      │                                      │
[ Storage Engine ]                 [ Hybrid Threat Engine ]               [ SOC Telemetry Engine ]
  ├─ Uploads (UUID Isolation)        ├─ Static Feature Extractor (30+)      ├─ Prometheus (/metrics)
  ├─ Quarantine Vault                ├─ Deterministic Heuristic Scanner     ├─ Grafana Dashboards
  ├─ Confidential Vault (AES-GCM)    ├─ Active ML Pipeline (RF/GB/LR)       ├─ Live VM Stats (psutil)
  └─ Recycle Bin (Soft Delete)       └─ Signal Fusion (Probabilities)       └─ Security Audit Logs
```

### Complete Machine Learning Lifecycle
```
DATASET DISCOVERY (CSV/JSON/Parquet)
  ↓
DATA INGESTION & QUALITY SCORING
  ↓
AUTOMATED DATA CLEANING (Deduplication, normalization, missing/infinite imputation)
  ↓
PREPROCESSING PIPELINE (ColumnTransformer, StandardScaler, OneHotEncoder)
  ↓
FEATURE ENGINEERING (Entropy, MIME mismatch, magic headers, macro, scripts, obfuscation)
  ↓
STRATIFIED TRAIN / VALIDATION / TEST SPLITTING (70% / 15% / 15%)
  ↓
CLASS IMBALANCE HANDLING (class_weight="balanced")
  ↓
MULTI-MODEL CANDIDATE TRAINING (Logistic Regression, Random Forest, Gradient Boosting, HistGradientBoosting)
  ↓
MODEL EVALUATION (Accuracy, Macro F1, Malicious Recall, ROC-AUC, Confusion Matrix)
  ↓
MODEL SELECTION (Prioritizing Malicious Threat Recall + Macro F1)
  ↓
MODEL PERSISTENCE (Joblib Sklearn Pipeline) & MODEL REGISTRY (model_registry.json)
  ↓
REAL-TIME HYBRID INFERENCE & THREAT SCORING
```

---

## 3. Technology Stack

- **Backend**: Python 3.10+, FastAPI, Uvicorn, SQLAlchemy, Pydantic v2, PyJWT, Bcrypt, Cryptography (AES-256-GCM, PBKDF2), Psutil.
- **Machine Learning**: Scikit-learn, Pandas, NumPy, Joblib, SciPy.
- **Document & Media Parsers**: `python-docx`, `openpyxl`, `python-pptx`, `Pillow`, `ReportLab`, `fpdf2`.
- **Telemetry & Monitoring**: Prometheus (OpenMetrics exposition), Grafana Dashboard schema, Web Audio API synthetic siren.
- **Frontend**: Responsive Single-Page Application, Cyber SOC Dark Theme, Tailwind CSS, Lucide Icons, Vanilla JS state architecture.

---

## 4. Key Capabilities & Security Controls

### A. Real-Time Hybrid Security Engine & Base Breach Alarm
- **Static Feature Extraction**: Extracts 30+ static parameters including Shannon entropy (0.0 to 8.0), magic byte signatures, MIME mismatches, double extension detection (`.pdf.exe`), obfuscation scores, script indicators, command patterns, and archive depths without executing code.
- **Heuristic Scanner**: Detects disguised executables, encoded PowerShell execution (`-enc`, `Invoke-Expression`), auto-executing VBA macros, living-off-the-land utilities (`certutil`, `bitsadmin`), and packed code.
- **Signal Fusion**: Computes transparent threat probabilities and composite threat scores.
- **Automatic Quarantine**: Files classified as `MALICIOUS` are instantly isolated into `/storage/quarantine/`, accompanied by a **3-second synthesized military security base breach alarm** that stops automatically after 3 seconds.

### B. Format-Preserving File Viewer (High-Contrast White Typography)
- **Strict Byte-Exact Integrity**: The original uploaded bytes are NEVER modified or rewritten. Downloads always match the pre-upload SHA-256 fingerprint (`HASH_A == HASH_B`).
- **DOCX Viewer**: Renders true document paragraphs, headings, and tables in crisp white font without raw ZIP or XML bytes.
- **XLSX Viewer**: Interactive spreadsheet tabs and cell grid renderer.
- **PPTX Viewer**: Slide deck slide-by-slide preview.
- **PDF, Image, Audio & Video**: Native streaming with full playback and pan/zoom.
- **ZIP Inspector**: Explores safe archive hierarchy without extraction or execution.
- **Unknown Binary**: Safe hexadecimal byte preview.

### C. Zero-Knowledge Confidential File Vault
- Users can lock sensitive documents behind a **6-digit PIN or strong password**.
- Encryption is performed with **AES-256-GCM** using keys derived via **PBKDF2-HMAC-SHA256 (100,000 iterations)**.
- **Administrator Isolation**: SOC Administrators can see metadata (filename, owner, size) but **CANNOT view or decrypt confidential content** without the user's PIN.

### D. Strict Role Separation & Security Governance
- **Server-Side Role Validation**: Users attempting to log into the Admin portal are rejected with HTTP 403 (`"Access denied: this account is registered as a User account and cannot be used with the Admin role."`).
- **Admin Account on User Portal**: Rejected with HTTP 403 (`"Access denied: this account is registered as an Admin account and cannot be used with the User role."`).
- **2FA TOTP**: Compatible with Google Authenticator.
- **Global Share Revocation**: Admin feature allowing instant invalidation of all public links.
- **IP Access Guard**: Whitelist and blacklist management with IP tracking.
- **Soft Deletion / Recycle Bin**: Files in recycle bin cannot be opened until restored.

---

## 5. One-Click Startup & Execution

### Option 1: Windows Batch File (Recommended - Double-Click)
Simply double-click:
```cmd
start_securecloud.bat
```
This script will:
1. Verify Python installation.
2. Initialize database and ML models.
3. Start the FastAPI backend at `http://127.0.0.1:8000`.
4. Start the frontend static server at `http://localhost:5500`.
5. Poll `http://127.0.0.1:8000/health` until healthy.
6. Automatically open `http://localhost:5500` in your default browser.

### Option 2: PowerShell Startup
```powershell
.\start_securecloud.ps1
```

### Option 3: Development Server Mode
```powershell
.\scripts\start-dev.ps1
```

### Graceful Targeted Shutdown
To stop only the SecureCloud services (ports 8000 & 5500) without affecting other applications:
```cmd
stop_securecloud.bat
```

---

## 6. Service URLs & Default Credentials

| Service | URL | Purpose |
|---|---|---|
| **Frontend Application** | `http://localhost:5500` | Web Interface |
| **Backend API Gateway** | `http://127.0.0.1:8000` | FastAPI Server |
| **Interactive API Docs** | `http://127.0.0.1:8000/docs` | Swagger UI |
| **Health Check** | `http://127.0.0.1:8000/health` | Service Liveness |
| **Prometheus Metrics** | `http://127.0.0.1:8000/metrics` | Telemetry Endpoint |

### Default Credentials

| Portal | Email | Password | Role |
|---|---|---|---|
| **Admin SOC Portal** | `admin@securecloud.com` | `AdminPass123!` | `ADMIN` |
| **User Vault Portal** | `analyst@securecloud.com` | `UserPass123!` | `USER` |

---

## 7. Running Acceptance Tests

To run the automated 38-step end-to-end acceptance suite:
```bash
python scripts/test_acceptance.py
```
Expected output:
```
======================================================================
ACCEPTANCE RESULTS: 38/38 STEPS PASSED (100% SUCCESS)
======================================================================
```

---

## 8. Monitoring & Telemetry Integration

### Prometheus
Configure `prometheus.yml` with:
```yaml
scrape_configs:
  - job_name: "securecloud_soc"
    metrics_path: "/metrics"
    static_configs:
      - targets: ["localhost:8000"]
```

### Grafana
Import `grafana/dashboards/securecloud_dashboard.json` into Grafana to visualize:
- CPU, Memory & Disk storage gauges
- API request rates & latency timeseries
- Threat scan rates & malicious quarantine counters
- Active user counts

---

## 9. Security Notice
*SecureCloud performs comprehensive static feature engineering, heuristic analysis, and machine learning threat classification. It is designed for secure enterprise cloud storage and SOC intelligence, operating safely without executing untrusted binaries.*
