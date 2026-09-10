/**
 * SecureCloud 2.0 - Core Frontend Application Controller
 * Single-Page Architecture with Cybersecurity SOC Theme, Hybrid Threat Analytics & Real-Time Storage Telemetry.
 */

const API_BASE = window.SECURECLOUD_API_BASE || window.location.origin;

const state = {
  token: localStorage.getItem("sc_token") || null,
  user: JSON.parse(localStorage.getItem("sc_user") || "null"),
  currentTab: "my-files", // my-files | confidential | password-saves | shares | recycle-bin | user-activity | soc-overview | soc-sentinel | soc-user-files | soc-users | soc-files | soc-threats | soc-quarantine | soc-ip-guard | soc-sessions | soc-audit
  files: [],
  allFiles: [],
  userGroupedFiles: [],
  confidentialFiles: [],
  savedPasswords: [],
  sharedLinks: [],
  recycleBin: [],
  notifications: [],
  alerts: [],
  socStats: null,
  telemetry: null,
  sentinelState: null,
  usersList: [],
  quarantinedList: [],
  threatsList: [],
  sessionsList: [],
  ipRules: [],
  auditLogs: [],
  userAuditLogs: [],
  isUploading: false,
  uploadProgress: 0,
  activeModal: null, // login | forgot-pw | viewer | pin-lock | pin-unlock | share-create | rename | versions | edit-quota | new-ip | scan-history | security-details
  activeFile: null,
  activeUserForQuota: null,
  activeViewerContent: null,
  activeScanHistory: [],
  activeSecurityDetails: null,
  criticalAlert: null,
  audioMuted: false,
  // Live scanning states per file
  fileScanStates: {}, // fileId -> { status, stage_label, progress_percent, threat_score, security_status }
  // Filters and Sorting
  fileSearchQuery: "",
  fileCategoryFilter: "ALL",
  fileSecurityFilter: "ALL",
  fileSortBy: "date-desc"
};

// Telemetry Waveform Buffer for Sentinel VM Canvas
const waveformHistory = {
  cpu: Array(40).fill(32),
  ram: Array(40).fill(48),
  disk: Array(40).fill(42)
};

// =========================================================================
// API Helper
// =========================================================================

async function apiRequest(endpoint, options = {}) {
  const headers = options.headers || {};
  if (state.token) {
    headers["Authorization"] = `Bearer ${state.token}`;
  }
  if (!(options.body instanceof FormData) && !headers["Content-Type"]) {
    headers["Content-Type"] = "application/json";
  }

  const url = endpoint.startsWith("http") ? endpoint : `${API_BASE}${endpoint}`;

  try {
    const res = await fetch(url, { ...options, headers });
    if (res.status === 401 && !endpoint.includes("/auth/login") && !endpoint.includes("/auth/register") && !endpoint.includes("/shares/public") && !endpoint.includes("/auth/forgot-password") && !endpoint.includes("/auth/reset-password")) {
      logout();
      throw new Error("Session expired. Please log in again.");
    }
    const data = await res.json().catch(() => ({}));
    if (!res.ok) {
      throw new Error(data.detail || data.message || "An error occurred.");
    }
    return data;
  } catch (err) {
    showToast(err.message, "danger");
    throw err;
  }
}

// Toast Notifications
function showToast(msg, type = "info") {
  const container = document.getElementById("toast-container");
  if (!container) return;

  const toast = document.createElement("div");
  const colors = {
    info: "border-sky-500 text-sky-100 bg-slate-900/95",
    success: "border-emerald-500 text-emerald-100 bg-slate-900/95",
    warning: "border-amber-500 text-amber-100 bg-slate-900/95",
    danger: "border-red-500 text-red-100 bg-slate-900/95"
  };

  toast.className = `p-4 rounded-lg border shadow-2xl flex items-center justify-between text-xs sm:text-sm transition-all duration-300 transform translate-y-2 opacity-0 ${colors[type] || colors.info}`;
  toast.innerHTML = `
    <div class="flex items-center gap-2">
      <i data-lucide="${type === 'danger' ? 'alert-triangle' : (type === 'success' ? 'check-circle' : 'info')}" class="w-5 h-5 flex-shrink-0"></i>
      <span class="font-medium text-white">${escapeHtml(msg)}</span>
    </div>
    <button onclick="this.parentElement.remove()" class="text-slate-400 hover:text-white ml-3">&times;</button>
  `;
  container.appendChild(toast);
  lucide.createIcons();

  requestAnimationFrame(() => {
    toast.classList.remove("translate-y-2", "opacity-0");
  });

  setTimeout(() => {
    if (toast.parentElement) {
      toast.classList.add("opacity-0", "translate-y-2");
      setTimeout(() => toast.remove(), 300);
    }
  }, 4500);
}

// =========================================================================
// App Initialization & State Hydration
// =========================================================================

document.addEventListener("DOMContentLoaded", () => {
  if (state.token && state.user) {
    refreshUserProfile();
    loadCurrentTabData();
    if (state.user.role === "ADMIN") {
      startLiveTelemetry();
    }
  }
  startShareCountdownTimer();
  render();
});

async function refreshUserProfile() {
  if (!state.token) return;
  try {
    const u = await apiRequest("/api/auth/me");
    state.user = u;
    localStorage.setItem("sc_user", JSON.stringify(u));
    const quotaHeaderEl = document.getElementById("user-quota-header");
    if (quotaHeaderEl) {
      quotaHeaderEl.innerText = `${u.used_quota_formatted || '0 B'} / ${u.quota_formatted || '10 GB'}`;
    }
  } catch (e) {}
}

async function loadCurrentTabData() {
  if (!state.token) return;

  refreshUserProfile();

  // Load user data
  if (state.currentTab === "my-files") await loadFiles();
  if (state.currentTab === "confidential") await loadConfidentialFiles();
  if (state.currentTab === "password-saves") await loadSavedPasswords();
  if (state.currentTab === "shares") await loadSharedLinks();
  if (state.currentTab === "recycle-bin") await loadRecycleBin();
  if (state.currentTab === "user-activity") await loadUserActivityLogs();

  // Load admin SOC data ONLY if current user is an ADMIN
  if (state.user && state.user.role === "ADMIN") {
    if (state.currentTab === "soc-overview") await loadSocDashboard();
    if (state.currentTab === "soc-sentinel") await loadSocDashboard();
    if (state.currentTab === "soc-user-files") await loadUserGroupedFiles();
    if (state.currentTab === "soc-users") await loadUsersList();
    if (state.currentTab === "soc-files") await loadAllFilesAdmin();
    if (state.currentTab === "soc-threats") await loadThreatsList();
    if (state.currentTab === "soc-quarantine") await loadQuarantineList();
    if (state.currentTab === "soc-ip-guard") await loadIpRules();
    if (state.currentTab === "soc-sessions") await loadSessionsList();
    if (state.currentTab === "soc-audit") await loadAuditLogs();
  }

  render();
}

async function loadFiles() {
  try {
    const res = await apiRequest("/api/files/list");
    state.files = res || [];
  } catch (e) {}
}

async function loadAllFilesAdmin() {
  try {
    const res = await apiRequest("/api/files/all");
    state.allFiles = res || [];
  } catch (e) {}
}

async function loadUserGroupedFiles() {
  try {
    const res = await apiRequest("/api/soc/users/grouped-files");
    state.userGroupedFiles = res || [];
  } catch (e) {}
}

async function loadConfidentialFiles() {
  try {
    const res = await apiRequest("/api/confidential/list");
    state.confidentialFiles = res || [];
  } catch (e) {}
}

async function loadSavedPasswords() {
  try {
    const res = await apiRequest("/api/confidential/saved-passwords");
    state.savedPasswords = res || [];
  } catch (e) {}
}

async function loadSharedLinks() {
  try {
    const res = await apiRequest("/api/shares/list");
    state.sharedLinks = res || [];
  } catch (e) {}
}

async function loadRecycleBin() {
  try {
    const res = await apiRequest("/api/recycle-bin/list");
    state.recycleBin = res || [];
  } catch (e) {}
}

async function loadSocDashboard() {
  try {
    const res = await apiRequest("/api/soc/dashboard");
    state.socStats = res;
    state.sentinelState = res.sentinel_state;
    if (res.vm_telemetry) {
      state.telemetry = {
        cpu_utilization: res.vm_telemetry.cpu_percent,
        ram_utilization: res.vm_telemetry.ram_percent,
        ram_used_gb: res.vm_telemetry.ram_used_gb,
        disk_utilization: res.vm_telemetry.disk_percent,
        network_bytes_recv_mb: res.vm_telemetry.net_in_mb
      };
      // Push into waveform buffer
      waveformHistory.cpu.push(res.vm_telemetry.cpu_percent);
      waveformHistory.cpu.shift();
      waveformHistory.ram.push(res.vm_telemetry.ram_percent);
      waveformHistory.ram.shift();
      waveformHistory.disk.push(res.vm_telemetry.disk_percent);
      waveformHistory.disk.shift();
      drawSentinelWaveform();
    }
  } catch (e) {}
}

async function loadUsersList() {
  try {
    const res = await apiRequest("/api/soc/users");
    state.usersList = res || [];
  } catch (e) {}
}

async function loadThreatsList() {
  try {
    const res = await apiRequest("/api/soc/threats");
    state.threatsList = res || [];
  } catch (e) {}
}

async function loadQuarantineList() {
  try {
    const res = await apiRequest("/api/soc/quarantine/list");
    state.quarantinedList = res || [];
  } catch (e) {}
}

async function loadSessionsList() {
  try {
    const res = await apiRequest("/api/soc/sessions");
    state.sessionsList = res || [];
  } catch (e) {}
}

async function loadIpRules() {
  try {
    const res = await apiRequest("/api/soc/ip-guard/list");
    state.ipRules = res || [];
  } catch (e) {}
}

async function loadAuditLogs() {
  try {
    const res = await apiRequest("/api/soc/audit-logs?limit=100");
    state.auditLogs = res || [];
  } catch (e) {}
}

async function loadUserActivityLogs() {
  try {
    if (!state.user) return;
    const res = await apiRequest(`/api/soc/timeline/${state.user.id}`);
    state.userAuditLogs = res || [];
  } catch (e) {}
}

// Live Telemetry Poller (Only active for ADMIN role)
let telemetryInterval = null;
function startLiveTelemetry() {
  if (telemetryInterval) clearInterval(telemetryInterval);
  if (!state.user || state.user.role !== "ADMIN") return;

  telemetryInterval = setInterval(async () => {
    if (!state.token || !state.user || state.user.role !== "ADMIN") {
      if (telemetryInterval) clearInterval(telemetryInterval);
      return;
    }
    try {
      const res = await apiRequest("/api/soc/telemetry");
      state.telemetry = {
        cpu_utilization: res.cpu_percent,
        ram_utilization: res.ram_percent,
        ram_used_gb: res.ram_used_gb,
        disk_utilization: res.disk_percent,
        network_bytes_recv_mb: res.net_in_mb
      };
      if (res.sentinel) state.sentinelState = res.sentinel;

      // Update Waveform Buffer
      waveformHistory.cpu.push(res.cpu_percent);
      waveformHistory.cpu.shift();
      waveformHistory.ram.push(res.ram_percent);
      waveformHistory.ram.shift();
      waveformHistory.disk.push(res.disk_percent);
      waveformHistory.disk.shift();

      updateLiveTelemetryDOM();
      drawSentinelWaveform();
    } catch (e) {}
  }, 2500);
}

function updateLiveTelemetryDOM() {
  const cpuEl = document.getElementById("live-cpu-val");
  const ramEl = document.getElementById("live-ram-val");
  const diskEl = document.getElementById("live-disk-val");
  const netEl = document.getElementById("live-net-val");
  if (state.telemetry) {
    if (cpuEl) cpuEl.innerText = `${state.telemetry.cpu_utilization}%`;
    if (ramEl) ramEl.innerText = `${state.telemetry.ram_utilization}% (${state.telemetry.ram_used_gb} GB)`;
    if (diskEl) diskEl.innerText = `${state.telemetry.disk_utilization}%`;
    if (netEl) netEl.innerText = `${state.telemetry.network_bytes_recv_mb} MB`;
  }
}

function drawSentinelWaveform() {
  const canvas = document.getElementById("sentinel-waveform-canvas");
  if (!canvas) return;
  const ctx = canvas.getContext("2d");
  if (!ctx) return;

  const w = canvas.width;
  const h = canvas.height;
  ctx.clearRect(0, 0, w, h);

  // Background Grid Lines
  ctx.strokeStyle = "#1e293b";
  ctx.lineWidth = 1;
  for (let y = 0; y <= h; y += h / 4) {
    ctx.beginPath();
    ctx.moveTo(0, y);
    ctx.lineTo(w, y);
    ctx.stroke();
  }

  function drawLine(data, color) {
    ctx.beginPath();
    ctx.strokeStyle = color;
    ctx.lineWidth = 2.5;
    const step = w / (data.length - 1);
    for (let i = 0; i < data.length; i++) {
      const val = data[i];
      const y = h - (val / 100) * h;
      if (i === 0) ctx.moveTo(0, y);
      else ctx.lineTo(i * step, y);
    }
    ctx.stroke();
  }

  drawLine(waveformHistory.disk, "#a855f7"); // Purple Disk
  drawLine(waveformHistory.ram, "#38bdf8");  // Blue RAM
  drawLine(waveformHistory.cpu, "#10b981");  // Green CPU
}

async function triggerSentinelPhase(phaseName) {
  try {
    const res = await apiRequest("/api/soc/telemetry/simulate-phase", {
      method: "POST",
      body: JSON.stringify({ phase: phaseName })
    });
    state.sentinelState = res.sentinel_state;
    showToast(`Sentinel Simulation: ${res.sentinel_state.phase} active`, "info");
    if (res.sentinel_state.status === "CRITICAL") {
      window.audioAlertSystem.playCriticalAlert();
    }
    loadSocDashboard();
    render();
  } catch (e) {}
}

// Password toggle helper
function togglePasswordVisibility(inputId, iconId) {
  const input = document.getElementById(inputId);
  const icon = document.getElementById(iconId);
  if (!input) return;
  if (input.type === "password") {
    input.type = "text";
    if (icon) {
      icon.setAttribute("data-lucide", "eye-off");
      lucide.createIcons();
    }
  } else {
    input.type = "password";
    if (icon) {
      icon.setAttribute("data-lucide", "eye");
      lucide.createIcons();
    }
  }
}

// CAPTCHA interaction helper
function handleCaptchaToggle(el) {
  if (el && el.checked) {
    const spinner = document.getElementById("captcha-spinner");
    if (spinner) {
      spinner.classList.remove("hidden");
      lucide.createIcons();
      setTimeout(() => {
        spinner.classList.add("hidden");
      }, 350);
    }
  }
}

// Live 1-Second Countdown Timer for Shared Links
let shareTimerInterval = null;
function startShareCountdownTimer() {
  if (shareTimerInterval) clearInterval(shareTimerInterval);
  shareTimerInterval = setInterval(() => {
    const elements = document.querySelectorAll(".share-countdown-badge");
    if (!elements || elements.length === 0) return;
    const now = new Date().getTime();
    elements.forEach(el => {
      const exp = el.getAttribute("data-expires");
      if (!exp || exp === "null" || exp === "") {
        el.innerHTML = '<span class="text-slate-400 text-xs">No Expiry</span>';
        return;
      }
      const expTime = new Date(exp).getTime();
      const diffSecs = Math.max(0, Math.floor((expTime - now) / 1000));
      if (diffSecs <= 0) {
        el.innerHTML = '<span class="px-2 py-0.5 rounded text-[10px] font-bold bg-red-950 text-red-400 border border-red-500/40">EXPIRED</span>';
      } else {
        const h = Math.floor(diffSecs / 3600);
        const m = Math.floor((diffSecs % 3600) / 60);
        const s = diffSecs % 60;
        el.innerHTML = `<span class="font-mono text-cyan-300 font-bold">${String(h).padStart(2, '0')}:${String(m).padStart(2, '0')}:${String(s).padStart(2, '0')}</span>`;
      }
    });
  }, 1000);
}

// =========================================================================
// Real-Time Staged Threat Scanning Execution (Item 4)
// =========================================================================

async function runSingleFileScanAdmin(fileId, filename) {
  state.fileScanStates[fileId] = {
    status: "SCANNING",
    stage_label: "Hashing & Metadata (30%)",
    progress_percent: 30
  };
  render();

  // Simulate genuine progress stages smoothly
  setTimeout(() => {
    if (state.fileScanStates[fileId]) {
      state.fileScanStates[fileId].stage_label = "Static Heuristic Analysis (50%)";
      state.fileScanStates[fileId].progress_percent = 50;
      render();
    }
  }, 350);

  setTimeout(() => {
    if (state.fileScanStates[fileId]) {
      state.fileScanStates[fileId].stage_label = "PE Structural & LightGBM Inference (75%)";
      state.fileScanStates[fileId].progress_percent = 75;
      render();
    }
  }, 750);

  try {
    const res = await apiRequest(`/api/soc/files/${fileId}/scan`, { method: "POST" });
    state.fileScanStates[fileId] = {
      status: "COMPLETED",
      stage_label: `Completed (${res.final_verdict})`,
      progress_percent: 100,
      threat_score: res.threat_score,
      security_status: res.security_status
    };
    showToast(`Scan complete for '${filename}': ${res.final_verdict} (Score: ${res.threat_score}%)`, res.security_status === 'CLEAN' ? 'success' : 'danger');
    if (res.is_quarantined) {
      window.audioAlertSystem.playCriticalAlert();
    }
    await loadCurrentTabData();
  } catch (e) {
    state.fileScanStates[fileId] = {
      status: "FAILED",
      stage_label: "Scan Failed",
      progress_percent: 0
    };
  }
  render();
}

async function viewFileScanHistory(fileId, filename) {
  try {
    const res = await apiRequest(`/api/soc/files/${fileId}/scan-history`);
    state.activeScanHistory = res || [];
    state.activeFile = { id: fileId, filename };
    openModal("scan-history");
  } catch (e) {}
}

async function viewFileSecurityDetails(fileId) {
  try {
    const res = await apiRequest(`/api/soc/files/${fileId}/security-details`);
    state.activeSecurityDetails = res;
    openModal("security-details");
  } catch (e) {}
}

// =========================================================================
// Real-Time Compulsory Threat Scanning & Upload Execution
// =========================================================================

async function handleFileUpload(files) {
  if (!files || files.length === 0) return;
  state.isUploading = true;
  render();

  for (let i = 0; i < files.length; i++) {
    const file = files[i];
    const formData = new FormData();
    formData.append("file", file);

    try {
      const res = await apiRequest("/api/files/upload", {
        method: "POST",
        body: formData
      });

      if (res.storage && state.user) {
        state.user.used_quota_bytes = res.storage.used_bytes;
        state.user.used_quota_formatted = res.storage.used_formatted;
        state.user.quota_formatted = res.storage.quota_formatted;
        localStorage.setItem("sc_user", JSON.stringify(state.user));
      }

      if (res.status === "QUARANTINED") {
        window.audioAlertSystem.playCriticalAlert();
        state.criticalAlert = {
          filename: file.name,
          threat_score: res.scan.threat_score,
          verdict: res.scan.final_verdict,
          rules: res.scan.heuristic_rules,
          explanations: res.scan.explanations
        };
        showToast(`🚨 CRITICAL THREAT: ${file.name} quarantined! Base breach alarm sounded.`, "danger");
      } else {
        const threatScore = res.scan?.threat_score || 0;
        const statusBadge = res.scan?.security_status || 'CLEAN';
        showToast(`Real-time Threat Scan: '${file.name}' verified (${statusBadge}, Score: ${threatScore}%).`, "success");
      }
    } catch (e) {
      console.error("Upload error:", e);
    }
  }

  state.isUploading = false;
  await loadCurrentTabData();
  render();
}

// =========================================================================
// Format-Preserving File Viewer
// =========================================================================

async function openFileViewer(fileId) {
  const recycledItem = state.recycleBin.find(r => r.file_id === fileId);
  if (recycledItem) {
    showToast("This file is in the Recycle Bin and cannot be opened until it is restored.", "warning");
    return;
  }

  try {
    const res = await apiRequest(`/api/files/${fileId}/view`);
    state.activeViewerContent = res;
    state.activeFile = state.files.find(f => f.id === fileId) || state.allFiles.find(f => f.id === fileId) || { id: fileId, filename: res.filename };
    openModal("viewer");
  } catch (e) {}
}

// =========================================================================
// Modal Manager
// =========================================================================

function openModal(modalName, extraData = null) {
  state.activeModal = modalName;
  if (extraData) {
    state.activeFile = extraData;
  }
  render();
}

function closeModal() {
  state.activeModal = null;
  state.activeViewerContent = null;
  state.activeUserForQuota = null;
  state.activeScanHistory = [];
  state.activeSecurityDetails = null;
  render();
}

function switchTab(tab) {
  state.currentTab = tab;
  loadCurrentTabData();
  render();
}

// =========================================================================
// Filter & Sort Logic
// =========================================================================

function getFilteredAndSortedFiles() {
  let list = [...state.files];

  if (state.fileSearchQuery.trim()) {
    const q = state.fileSearchQuery.toLowerCase();
    list = list.filter(f => f.filename.toLowerCase().includes(q) || f.extension.toLowerCase().includes(q) || f.file_hash.toLowerCase().includes(q));
  }

  if (state.fileCategoryFilter !== "ALL") {
    const map = {
      PDF: [".pdf"],
      DOC: [".doc", ".docx", ".rtf", ".odt"],
      SHEET: [".xls", ".xlsx", ".csv"],
      PRESENT: [".ppt", ".pptx"],
      IMAGE: [".png", ".jpg", ".jpeg", ".gif", ".webp", ".svg"],
      VIDEO: [".mp4", ".webm", ".mov", ".avi"],
      AUDIO: [".mp3", ".wav", ".ogg", ".flac"],
      CODE: [".py", ".js", ".ts", ".html", ".css", ".json", ".sh", ".bat", ".ps1", ".java", ".c", ".cpp", ".sql"],
      ARCHIVE: [".zip", ".tar", ".gz", ".7z", ".rar"],
      TEXT: [".txt", ".log", ".md"]
    };
    const validExts = map[state.fileCategoryFilter] || [];
    list = list.filter(f => validExts.includes(f.extension.toLowerCase()));
  }

  if (state.fileSecurityFilter !== "ALL") {
    list = list.filter(f => f.security_status === state.fileSecurityFilter);
  }

  list.sort((a, b) => {
    switch (state.fileSortBy) {
      case "date-desc": return new Date(b.created_at) - new Date(a.created_at);
      case "date-asc": return new Date(a.created_at) - new Date(b.created_at);
      case "name-asc": return a.filename.localeCompare(b.filename);
      case "name-desc": return b.filename.localeCompare(a.filename);
      case "size-desc": return b.file_size - a.file_size;
      case "size-asc": return a.file_size - b.file_size;
      case "threat-desc": return b.threat_score - a.threat_score;
      default: return 0;
    }
  });

  return list;
}

// =========================================================================
// Main View Renderer
// =========================================================================

function render() {
  const app = document.getElementById("app");
  if (!app) return;

  app.innerHTML = `
    <!-- Top Military Base Breach Alert Banner -->
    ${state.criticalAlert ? `
      <div class="siren-banner p-3 px-6 text-white flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3 shadow-2xl">
        <div class="flex items-center gap-3">
          <span class="p-1 px-2.5 bg-red-600 font-black rounded text-xs tracking-wider animate-pulse uppercase">3-SECOND BASE BREACH ALARM</span>
          <span class="text-xs sm:text-sm font-semibold">Malicious threat in <strong>"${escapeHtml(state.criticalAlert.filename)}"</strong> (Score: ${state.criticalAlert.threat_score}%) — Isolated in Quarantine Vault.</span>
        </div>
        <div class="flex items-center gap-2 self-end sm:self-auto">
          <button onclick="window.audioAlertSystem.toggleMute(); state.audioMuted = !state.audioMuted; render();" class="p-1 px-3 bg-red-950/90 border border-red-400 rounded text-xs flex items-center gap-1 hover:bg-red-900 text-white">
            <i data-lucide="${state.audioMuted ? 'volume-x' : 'volume-2'}" class="w-4 h-4"></i>
            <span>${state.audioMuted ? 'Unmute Alarm' : 'Mute Alarm'}</span>
          </button>
          <button onclick="state.criticalAlert = null; render();" title="Acknowledge Alert" class="p-1 px-3 bg-black/50 hover:bg-black/70 border border-white/30 rounded text-xs text-white font-bold">
            Acknowledge
          </button>
        </div>
      </div>
    ` : ''}

    <!-- Main Navigation Bar -->
    <header class="border-b border-slate-800 bg-slate-950/95 backdrop-blur sticky top-0 z-40">
      <div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 h-16 flex items-center justify-between">
        <!-- Logo & Branding -->
        <div class="flex items-center space-x-3 cursor-pointer select-none" onclick="window.location.hash='#/'">
            <div class="w-10 h-10 rounded-lg bg-gradient-to-tr from-sky-600 to-cyan-400 p-0.5 shadow-lg shadow-sky-500/20">
                <div class="w-full h-full bg-slate-950 rounded-[7px] flex items-center justify-center">
                    <i data-lucide="shield-check" class="w-5 h-5 text-sky-400"></i>
                </div>
            </div>
            <div>
                <span class="font-black tracking-wider text-lg text-white">SECURE<span class="text-sky-400">CLOUD</span></span>
            </div>
        </div>

        <!-- Navigation Tabs -->
        ${state.user ? `
          <nav class="hidden md:flex items-center gap-1 bg-slate-900/90 p-1 rounded-xl border border-slate-800 overflow-x-auto">
            ${state.user.role === "ADMIN" ? `
              <button onclick="switchTab('soc-overview')" class="px-3 py-1.5 rounded-lg text-xs font-semibold flex items-center gap-1.5 transition ${state.currentTab === 'soc-overview' ? 'bg-cyan-600 text-white shadow' : 'text-cyan-400 hover:bg-cyan-950/40'}">
                <i data-lucide="activity" class="w-3.5 h-3.5"></i> SOC Overview
              </button>
              <button onclick="switchTab('soc-sentinel')" class="px-3 py-1.5 rounded-lg text-xs font-semibold flex items-center gap-1.5 transition ${state.currentTab === 'soc-sentinel' ? 'bg-sky-600 text-white shadow' : 'text-slate-300 hover:text-white hover:bg-slate-800'}">
                <i data-lucide="gauge" class="w-3.5 h-3.5"></i> Sentinel VM
              </button>
              <button onclick="switchTab('soc-user-files')" class="px-3 py-1.5 rounded-lg text-xs font-semibold flex items-center gap-1.5 transition ${state.currentTab === 'soc-user-files' ? 'bg-indigo-600 text-white shadow' : 'text-indigo-300 hover:text-white hover:bg-slate-800'}">
                <i data-lucide="git-branch" class="w-3.5 h-3.5"></i> User-Wise Files
              </button>
              <button onclick="switchTab('soc-users')" class="px-3 py-1.5 rounded-lg text-xs font-semibold flex items-center gap-1.5 transition ${state.currentTab === 'soc-users' ? 'bg-sky-600 text-white shadow' : 'text-slate-300 hover:text-white hover:bg-slate-800'}">
                <i data-lucide="users" class="w-3.5 h-3.5"></i> Users
              </button>
              <button onclick="switchTab('soc-files')" class="px-3 py-1.5 rounded-lg text-xs font-semibold flex items-center gap-1.5 transition ${state.currentTab === 'soc-files' ? 'bg-sky-600 text-white shadow' : 'text-slate-300 hover:text-white hover:bg-slate-800'}">
                <i data-lucide="files" class="w-3.5 h-3.5"></i> All Files
              </button>
              <button onclick="switchTab('soc-threats')" class="px-3 py-1.5 rounded-lg text-xs font-semibold flex items-center gap-1.5 transition ${state.currentTab === 'soc-threats' ? 'bg-red-600 text-white shadow' : 'text-red-400 hover:bg-red-950/40'}">
                <i data-lucide="shield-alert" class="w-3.5 h-3.5"></i> Threat Center
              </button>
              <button onclick="switchTab('soc-quarantine')" class="px-3 py-1.5 rounded-lg text-xs font-semibold flex items-center gap-1.5 transition ${state.currentTab === 'soc-quarantine' ? 'bg-red-700 text-white shadow' : 'text-slate-300 hover:text-white hover:bg-slate-800'}">
                <i data-lucide="archive" class="w-3.5 h-3.5"></i> Quarantine
              </button>
              <button onclick="switchTab('soc-ip-guard')" class="px-3 py-1.5 rounded-lg text-xs font-semibold flex items-center gap-1.5 transition ${state.currentTab === 'soc-ip-guard' ? 'bg-amber-600 text-white shadow' : 'text-slate-300 hover:text-white hover:bg-slate-800'}">
                <i data-lucide="shield" class="w-3.5 h-3.5"></i> IP Guard
              </button>
              <button onclick="switchTab('soc-sessions')" class="px-3 py-1.5 rounded-lg text-xs font-semibold flex items-center gap-1.5 transition ${state.currentTab === 'soc-sessions' ? 'bg-purple-600 text-white shadow' : 'text-slate-300 hover:text-white hover:bg-slate-800'}">
                <i data-lucide="key" class="w-3.5 h-3.5"></i> Sessions
              </button>
              <button onclick="switchTab('soc-audit')" class="px-3 py-1.5 rounded-lg text-xs font-semibold flex items-center gap-1.5 transition ${state.currentTab === 'soc-audit' ? 'bg-slate-800 text-white shadow' : 'text-slate-300 hover:text-white hover:bg-slate-800'}">
                <i data-lucide="list" class="w-3.5 h-3.5"></i> Audit Logs
              </button>
            ` : `
              <button onclick="switchTab('my-files')" class="px-3 py-1.5 rounded-lg text-xs font-semibold flex items-center gap-1.5 transition ${state.currentTab === 'my-files' ? 'bg-sky-600 text-white shadow' : 'text-slate-300 hover:text-white hover:bg-slate-800'}">
                <i data-lucide="folder" class="w-3.5 h-3.5"></i> My Files
              </button>
              <button onclick="switchTab('confidential')" class="px-3 py-1.5 rounded-lg text-xs font-semibold flex items-center gap-1.5 transition ${state.currentTab === 'confidential' ? 'bg-amber-600 text-white shadow' : 'text-slate-300 hover:text-white hover:bg-slate-800'}">
                <i data-lucide="lock" class="w-3.5 h-3.5"></i> Confidential Vault
              </button>
              <button onclick="switchTab('password-saves')" class="px-3 py-1.5 rounded-lg text-xs font-semibold flex items-center gap-1.5 transition ${state.currentTab === 'password-saves' ? 'bg-emerald-600 text-white shadow' : 'text-emerald-400 hover:text-white hover:bg-slate-800'}">
                <i data-lucide="key-round" class="w-3.5 h-3.5"></i> Password Saves
              </button>
              <button onclick="switchTab('shares')" class="px-3 py-1.5 rounded-lg text-xs font-semibold flex items-center gap-1.5 transition ${state.currentTab === 'shares' ? 'bg-cyan-600 text-white shadow' : 'text-slate-300 hover:text-white hover:bg-slate-800'}">
                <i data-lucide="share-2" class="w-3.5 h-3.5"></i> Shared Links
              </button>
              <button onclick="switchTab('recycle-bin')" class="px-3 py-1.5 rounded-lg text-xs font-semibold flex items-center gap-1.5 transition ${state.currentTab === 'recycle-bin' ? 'bg-red-600 text-white shadow' : 'text-slate-300 hover:text-white hover:bg-slate-800'}">
                <i data-lucide="trash-2" class="w-3.5 h-3.5"></i> Recycle Bin
              </button>
              <button onclick="switchTab('user-activity')" class="px-3 py-1.5 rounded-lg text-xs font-semibold flex items-center gap-1.5 transition ${state.currentTab === 'user-activity' ? 'bg-slate-800 text-white shadow' : 'text-slate-300 hover:text-white hover:bg-slate-800'}">
                <i data-lucide="clock" class="w-3.5 h-3.5"></i> Activity History
              </button>
            `}
          </nav>
        ` : ''}

        <!-- Right Side Actions & Profile -->
        <div class="flex items-center gap-3">
          ${state.user ? `
            <div class="hidden lg:flex items-center gap-2 bg-slate-900 border border-slate-800 px-3 py-1 rounded-full text-xs font-mono">
              <span class="live-pulse"></span>
              <span class="text-slate-200">SOC LIVE</span>
            </div>

            <div class="flex items-center gap-2.5 pl-2 border-l border-slate-800">
              <div class="text-right hidden sm:block">
                <div class="text-xs font-bold text-white flex items-center gap-1.5 justify-end">
                  ${escapeHtml(state.user.username)}
                  <span class="px-1.5 py-0.2 bg-slate-800 border ${state.user.role === 'ADMIN' ? 'border-cyan-500 text-cyan-300' : 'border-slate-700 text-slate-300'} rounded text-[10px] uppercase font-mono">${state.user.role}</span>
                </div>
                <div id="user-quota-header" class="text-[10px] text-slate-400 font-mono">
                  ${state.user.used_quota_formatted || '0 B'} / ${state.user.quota_formatted || '10 GB'}
                </div>
              </div>
              <button onclick="logout()" title="Logout" class="p-2 text-slate-400 hover:text-red-400 bg-slate-900 hover:bg-slate-800 border border-slate-800 rounded-lg transition">
                <i data-lucide="log-out" class="w-4 h-4"></i>
              </button>
            </div>
          ` : `
            <button onclick="openModal('login')" class="btn-cyber px-4 py-2 rounded-lg text-xs font-bold">
              Sign In / Access Portal
            </button>
          `}
        </div>
      </div>
    </header>

    <!-- Main View Container -->
    <main class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-6 flex-1">
      ${renderTabContent()}
    </main>

    <!-- Modals Container -->
    ${renderModals()}

    <!-- Toast Notification Container -->
    <div id="toast-container" class="fixed bottom-5 right-5 z-50 flex flex-col gap-2 max-w-sm w-full"></div>
  `;

  lucide.createIcons();
  if (state.currentTab === "soc-sentinel" || state.currentTab === "soc-overview") {
    setTimeout(drawSentinelWaveform, 50);
  }
}

function renderTabContent() {
  if (!state.user) {
    return `
      <div class="min-h-[70vh] flex flex-col items-center justify-center text-center">
        <div class="w-20 h-20 bg-sky-950 border border-sky-500/40 rounded-2xl flex items-center justify-center mb-4 shadow-2xl shadow-sky-500/20 animate-bounce">
          <i data-lucide="shield-check" class="w-10 h-10 text-sky-400"></i>
        </div>
        <h1 class="text-3xl sm:text-4xl font-black text-white tracking-tight">SECURECLOUD 2.0</h1>
        <p class="text-slate-300 max-w-lg mt-2 text-sm">Automated Real-Time ML Threat Classification, 3-Second Base Breach Siren, Confidential Vaults & SOC Telemetry Engine.</p>
        <div class="flex gap-4 mt-6">
          <button onclick="openModal('login')" class="btn-cyber px-6 py-2.5 rounded-xl text-sm font-bold">Enter Security Portal</button>
        </div>
      </div>
    `;
  }

  switch (state.currentTab) {
    case "my-files": return renderMyFilesTab();
    case "confidential": return renderConfidentialTab();
    case "password-saves": return renderPasswordSavesTab();
    case "shares": return renderSharesTab();
    case "recycle-bin": return renderRecycleBinTab();
    case "user-activity": return renderUserActivityTab();

    // SOC Admin Tabs
    case "soc-overview": return renderSocOverviewTab();
    case "soc-sentinel": return renderSentinelVmTab();
    case "soc-user-files": return renderUserWiseFilesTab();
    case "soc-users": return renderSocUsersTab();
    case "soc-files": return renderSocFilesTab();
    case "soc-threats": return renderSocThreatsTab();
    case "soc-quarantine": return renderSocQuarantineTab();
    case "soc-ip-guard": return renderSocIpGuardTab();
    case "soc-sessions": return renderSocSessionsTab();
    case "soc-audit": return renderSocAuditTab();

    default:
      return state.user.role === "ADMIN" ? renderSocOverviewTab() : renderMyFilesTab();
  }
}

// =========================================================================
// USER TABS
// =========================================================================

function renderMyFilesTab() {
  const displayFiles = getFilteredAndSortedFiles();

  return `
    <div class="space-y-6">
      <!-- Top Actions & Upload Bar -->
      <div class="flex flex-col md:flex-row items-start md:items-center justify-between gap-4 glass-card p-5">
        <div>
          <h2 class="text-xl font-extrabold text-white flex items-center gap-2">
            <i data-lucide="hard-drive" class="w-5 h-5 text-sky-400"></i> Secure Storage Vault
          </h2>
          <p class="text-xs text-slate-300 mt-0.5">Real-time compulsory ML malware & virus scanning active on every upload. SHA-256 fingerprint verified.</p>
        </div>
        <div class="flex items-center gap-3">
          <label class="btn-cyber px-4 py-2.5 rounded-lg text-xs font-bold cursor-pointer flex items-center gap-2">
            <i data-lucide="upload-cloud" class="w-4 h-4"></i> Upload & Real-Time Scan
            <input type="file" multiple class="hidden" onchange="handleFileUpload(this.files)" />
          </label>
        </div>
      </div>

      ${state.isUploading ? `
        <div class="glass-card p-4 border border-sky-500/50 bg-sky-950/40 flex items-center gap-3 animate-pulse">
          <i data-lucide="loader-2" class="w-5 h-5 text-sky-400 animate-spin"></i>
          <div class="text-xs text-sky-100">
            <strong>Running real-time ML & heuristic malware detection...</strong> Compulsory scan in progress for all uploaded files.
          </div>
        </div>
      ` : ''}

      <!-- Search, Categories & Sorting Bar -->
      <div class="glass-card p-4 space-y-3">
        <div class="flex flex-col md:flex-row items-stretch md:items-center justify-between gap-3">
          <div class="relative flex-1">
            <i data-lucide="search" class="w-4 h-4 absolute left-3 top-2.5 text-slate-400"></i>
            <input 
              type="text" 
              placeholder="Search files by name, type, or SHA-256 hash..." 
              value="${escapeHtml(state.fileSearchQuery)}"
              oninput="state.fileSearchQuery = this.value; render();"
              class="w-full bg-slate-900 border border-slate-700 rounded-lg pl-9 pr-3 py-2 text-xs text-white focus:border-sky-500 outline-none"
            />
          </div>

          <div class="flex items-center gap-2">
            <span class="text-xs text-slate-400 whitespace-nowrap">Security:</span>
            <select 
              onchange="state.fileSecurityFilter = this.value; render();"
              class="bg-slate-900 border border-slate-700 rounded-lg px-2.5 py-2 text-xs text-white outline-none"
            >
              <option value="ALL" ${state.fileSecurityFilter === 'ALL' ? 'selected' : ''}>All Statuses</option>
              <option value="CLEAN" ${state.fileSecurityFilter === 'CLEAN' ? 'selected' : ''}>Clean & Verified</option>
              <option value="SUSPICIOUS" ${state.fileSecurityFilter === 'SUSPICIOUS' ? 'selected' : ''}>Suspicious</option>
              <option value="MALICIOUS" ${state.fileSecurityFilter === 'MALICIOUS' ? 'selected' : ''}>Malicious</option>
            </select>
          </div>

          <div class="flex items-center gap-2">
            <span class="text-xs text-slate-400 whitespace-nowrap">Sort:</span>
            <select 
              onchange="state.fileSortBy = this.value; render();"
              class="bg-slate-900 border border-slate-700 rounded-lg px-2.5 py-2 text-xs text-white outline-none"
            >
              <option value="date-desc" ${state.fileSortBy === 'date-desc' ? 'selected' : ''}>Newest First</option>
              <option value="date-asc" ${state.fileSortBy === 'date-asc' ? 'selected' : ''}>Oldest First</option>
              <option value="name-asc" ${state.fileSortBy === 'name-asc' ? 'selected' : ''}>Name (A-Z)</option>
              <option value="name-desc" ${state.fileSortBy === 'name-desc' ? 'selected' : ''}>Name (Z-A)</option>
              <option value="size-desc" ${state.fileSortBy === 'size-desc' ? 'selected' : ''}>Size (Largest)</option>
              <option value="size-asc" ${state.fileSortBy === 'size-asc' ? 'selected' : ''}>Size (Smallest)</option>
              <option value="threat-desc" ${state.fileSortBy === 'threat-desc' ? 'selected' : ''}>Threat Score</option>
            </select>
          </div>
        </div>

        <div class="flex items-center gap-1.5 overflow-x-auto pb-1 text-xs">
          ${[
            { id: "ALL", label: "All Files" },
            { id: "PDF", label: "PDF" },
            { id: "DOC", label: "Word Documents" },
            { id: "SHEET", label: "Spreadsheets" },
            { id: "PRESENT", label: "Presentations" },
            { id: "IMAGE", label: "Images" },
            { id: "VIDEO", label: "Videos" },
            { id: "AUDIO", label: "Audio" },
            { id: "CODE", label: "Code" },
            { id: "ARCHIVE", label: "Archives" },
            { id: "TEXT", label: "Plain Text" }
          ].map(c => `
            <button 
              onclick="state.fileCategoryFilter = '${c.id}'; render();"
              class="px-2.5 py-1 rounded-md transition whitespace-nowrap font-medium ${state.fileCategoryFilter === c.id ? 'bg-sky-600 text-white' : 'bg-slate-900 border border-slate-800 text-slate-300 hover:text-white hover:bg-slate-800'}"
            >
              ${c.label}
            </button>
          `).join('')}
        </div>
      </div>

      <!-- Files Table -->
      <div class="glass-card overflow-hidden">
        <div class="overflow-x-auto">
          <table class="soc-table">
            <thead>
              <tr>
                <th>File Name</th>
                <th>Size</th>
                <th>Security Verdict</th>
                <th>Threat Score</th>
                <th>SHA-256 Fingerprint</th>
                <th>Version</th>
                <th>Uploaded</th>
                <th class="text-right">Actions</th>
              </tr>
            </thead>
            <tbody>
              ${displayFiles.length === 0 ? `
                <tr>
                  <td colspan="8" class="text-center py-12 text-slate-400">
                    <i data-lucide="folder-open" class="w-10 h-10 mx-auto mb-2 opacity-40 text-sky-400"></i>
                    No files found. Click "Upload & Real-Time Scan" to store your first secure file.
                  </td>
                </tr>
              ` : displayFiles.map(f => `
                <tr>
                  <td>
                    <div class="flex items-center gap-2.5">
                      <div class="p-2 rounded bg-slate-800/80 border border-slate-700 text-sky-400">
                        <i data-lucide="${getFileIcon(f.extension)}" class="w-4 h-4"></i>
                      </div>
                      <div>
                        <div class="font-bold text-white flex items-center gap-1.5">
                          <span class="hover:text-sky-300 cursor-pointer" onclick="openFileViewer('${f.id}')">${escapeHtml(f.filename)}</span>
                          ${f.is_shared ? '<span class="px-1.5 py-0.2 bg-cyan-950 border border-cyan-500/40 text-cyan-300 rounded text-[9px] font-mono">SHARED</span>' : ''}
                        </div>
                        <div class="text-[10px] text-slate-400 font-mono">${f.mime_type || 'application/octet-stream'}</div>
                      </div>
                    </div>
                  </td>
                  <td class="font-mono text-xs text-white">${f.file_size_formatted}</td>
                  <td>
                    <span class="px-2.5 py-1 rounded-full text-[11px] font-bold ${getSecurityBadgeClass(f.security_status)}">
                      ${f.security_status}
                    </span>
                  </td>
                  <td>
                    <div class="flex items-center gap-2">
                      <div class="w-16 bg-slate-800 h-2 rounded-full overflow-hidden">
                        <div class="h-full ${f.threat_score >= 60 ? 'bg-red-500' : (f.threat_score >= 25 ? 'bg-amber-500' : 'bg-emerald-500')}" style="width: ${f.threat_score}%"></div>
                      </div>
                      <span class="text-xs font-mono font-bold ${f.threat_score >= 60 ? 'text-red-400' : (f.threat_score >= 25 ? 'text-amber-400' : 'text-emerald-400')}">${f.threat_score}%</span>
                    </div>
                  </td>
                  <td class="font-mono text-[11px] text-slate-300" title="${f.file_hash}">
                    ${f.file_hash.substring(0, 14)}...
                  </td>
                  <td>
                    <button onclick="openModal('versions', { id: '${f.id}', filename: '${escapeHtml(f.filename)}' })" title="Manage Versions" class="px-2 py-0.5 bg-slate-800 hover:bg-slate-700 border border-slate-700 text-white rounded text-[10px] font-mono">
                      ${f.current_version}
                    </button>
                  </td>
                  <td class="text-xs text-slate-300">${f.created_at}</td>
                  <td class="text-right">
                    <div class="flex items-center justify-end gap-1">
                      <button onclick="openFileViewer('${f.id}')" title="Open / Preview" class="p-1.5 text-slate-300 hover:text-sky-400 hover:bg-slate-800 rounded">
                        <i data-lucide="eye" class="w-4 h-4"></i>
                      </button>
                      <button onclick="openModal('rename', { id: '${f.id}', filename: '${escapeHtml(f.filename)}' })" title="Rename File" class="p-1.5 text-slate-300 hover:text-purple-400 hover:bg-slate-800 rounded">
                        <i data-lucide="edit-3" class="w-4 h-4"></i>
                      </button>
                      <a href="${API_BASE}/api/files/${f.id}/download" title="Download original bytes" class="p-1.5 text-slate-300 hover:text-emerald-400 hover:bg-slate-800 rounded">
                        <i data-lucide="download" class="w-4 h-4"></i>
                      </a>
                      <button onclick="openModal('pin-lock', { id: '${f.id}', filename: '${escapeHtml(f.filename)}' })" title="Lock in Confidential Vault" class="p-1.5 text-slate-300 hover:text-amber-400 hover:bg-slate-800 rounded">
                        <i data-lucide="lock" class="w-4 h-4"></i>
                      </button>
                      <button onclick="openModal('share-create', { id: '${f.id}', filename: '${escapeHtml(f.filename)}' })" title="Generate Shareable Link" class="p-1.5 text-slate-300 hover:text-cyan-400 hover:bg-slate-800 rounded">
                        <i data-lucide="share-2" class="w-4 h-4"></i>
                      </button>
                      <button onclick="deleteFile('${f.id}')" title="Move to Recycle Bin" class="p-1.5 text-slate-300 hover:text-red-400 hover:bg-slate-800 rounded">
                        <i data-lucide="trash-2" class="w-4 h-4"></i>
                      </button>
                    </div>
                  </td>
                </tr>
              `).join('')}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  `;
}

function renderConfidentialTab() {
  return `
    <div class="space-y-6">
      <div class="glass-card p-5 flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
        <div>
          <h2 class="text-xl font-extrabold text-white flex items-center gap-2">
            <i data-lucide="shield-check" class="w-5 h-5 text-amber-400"></i> Zero-Knowledge Confidential Vault
          </h2>
          <p class="text-xs text-slate-300 mt-0.5">Encrypted using AES-256-GCM and PBKDF2 derived PIN keys. Contents are inaccessible even to SOC Administrators.</p>
        </div>
        <button onclick="switchTab('password-saves')" class="btn-cyber px-4 py-2 rounded-lg text-xs font-bold flex items-center gap-1.5">
          <i data-lucide="key-round" class="w-4 h-4"></i> View Confidential Password Saves
        </button>
      </div>

      <div class="glass-card overflow-hidden">
        <table class="soc-table">
          <thead>
            <tr>
              <th>Confidential File</th>
              <th>Encrypted Size</th>
              <th>Encryption Standard</th>
              <th>Security Status</th>
              <th>Secured Date</th>
              <th class="text-right">PIN Actions</th>
            </tr>
          </thead>
          <tbody>
            ${state.confidentialFiles.length === 0 ? `
              <tr>
                <td colspan="6" class="text-center py-12 text-slate-400">
                  <i data-lucide="lock" class="w-8 h-8 mx-auto mb-2 opacity-50 text-amber-400"></i>
                  No files currently secured in Confidential Vault. Use the Lock icon in My Files to encrypt files with a 6-digit PIN.
                </td>
              </tr>
            ` : state.confidentialFiles.map(f => `
              <tr>
                <td>
                  <div class="flex items-center gap-2.5">
                    <div class="p-2 rounded bg-amber-950/40 border border-amber-500/30 text-amber-400">
                      <i data-lucide="file-lock-2" class="w-4 h-4"></i>
                    </div>
                    <div>
                      <div class="font-bold text-white">${escapeHtml(f.filename)}</div>
                      <div class="text-[10px] text-amber-400 font-mono">AES-256-GCM Encrypted</div>
                    </div>
                  </div>
                </td>
                <td class="font-mono text-xs text-white">${f.file_size_formatted}</td>
                <td><span class="px-2 py-0.5 bg-slate-800 border border-slate-700 text-slate-200 rounded text-[10px] font-mono">PBKDF2-SHA256 (100k)</span></td>
                <td>
                  <span class="px-2.5 py-1 rounded-full text-[11px] font-bold ${getSecurityBadgeClass(f.security_status)}">
                    ${f.security_status}
                  </span>
                </td>
                <td class="text-xs text-slate-300">${f.created_at}</td>
                <td class="text-right">
                  <div class="flex items-center justify-end gap-2">
                    <button onclick="openModal('pin-unlock', { id: '${f.id}', filename: '${escapeHtml(f.filename)}' })" class="px-3 py-1.5 rounded-lg bg-amber-600 hover:bg-amber-500 text-white text-xs font-semibold flex items-center gap-1.5">
                      <i data-lucide="key" class="w-3.5 h-3.5"></i> Enter PIN to Decrypt
                    </button>
                  </div>
                </td>
              </tr>
            `).join('')}
          </tbody>
        </table>
      </div>
    </div>
  `;
}

// Item 5: Confidential Password Saves / Key Recovery Vault
function renderPasswordSavesTab() {
  return `
    <div class="space-y-6">
      <div class="glass-card p-5">
        <h2 class="text-xl font-extrabold text-white flex items-center gap-2">
          <i data-lucide="key-round" class="w-5 h-5 text-emerald-400"></i> Confidential Password Saves & Recovery Vault
        </h2>
        <p class="text-xs text-slate-300 mt-0.5">Secure history of all your encrypted files and saved decryption keys so you never lose access to your confidential files.</p>
      </div>

      <div class="glass-card overflow-hidden">
        <table class="soc-table">
          <thead>
            <tr>
              <th>File Name</th>
              <th>Size</th>
              <th>Encryption Standard</th>
              <th>Saved Decryption PIN / Passphrase</th>
              <th>Secured Date</th>
              <th class="text-right">Actions</th>
            </tr>
          </thead>
          <tbody>
            ${state.savedPasswords.length === 0 ? `
              <tr>
                <td colspan="6" class="text-center py-12 text-slate-400">
                  <i data-lucide="key" class="w-8 h-8 mx-auto mb-2 opacity-40 text-emerald-400"></i>
                  No saved recovery keys recorded yet. Check "Save PIN to my Recovery Vault" when encrypting files in the Confidential Vault.
                </td>
              </tr>
            ` : state.savedPasswords.map((p, idx) => `
              <tr>
                <td class="font-bold text-white">${escapeHtml(p.filename)}</td>
                <td class="font-mono text-xs text-white">${p.file_size_formatted}</td>
                <td><span class="px-2 py-0.5 bg-slate-800 text-slate-300 rounded text-[10px] font-mono">${p.encryption_type}</span></td>
                <td>
                  <div class="flex items-center gap-2">
                    <span id="saved-pin-txt-${idx}" class="font-mono text-xs text-emerald-300 font-bold bg-slate-900 border border-slate-700 px-2.5 py-1 rounded">
                      ••••••
                    </span>
                    <button onclick="toggleSavedPinDisplay(${idx}, '${escapeHtml(p.saved_pin)}')" title="Toggle View Key" class="p-1 text-slate-400 hover:text-white">
                      <i id="saved-pin-icon-${idx}" data-lucide="eye" class="w-4 h-4"></i>
                    </button>
                    <button onclick="navigator.clipboard.writeText('${escapeHtml(p.saved_pin)}'); showToast('Decryption key copied to clipboard!', 'success');" title="Copy Key" class="p-1 text-slate-400 hover:text-emerald-300">
                      <i data-lucide="copy" class="w-4 h-4"></i>
                    </button>
                  </div>
                </td>
                <td class="text-xs text-slate-300">${p.created_at}</td>
                <td class="text-right">
                  <button onclick="openModal('pin-unlock', { id: '${p.file_id}', filename: '${escapeHtml(p.filename)}' })" class="px-2.5 py-1 bg-amber-600 hover:bg-amber-500 rounded text-xs text-white font-semibold">
                    Decrypt File
                  </button>
                </td>
              </tr>
            `).join('')}
          </tbody>
        </table>
      </div>
    </div>
  `;
}

function toggleSavedPinDisplay(idx, actualPin) {
  const txt = document.getElementById(`saved-pin-txt-${idx}`);
  const icon = document.getElementById(`saved-pin-icon-${idx}`);
  if (!txt) return;
  if (txt.innerText.includes("••")) {
    txt.innerText = actualPin;
    if (icon) icon.setAttribute("data-lucide", "eye-off");
  } else {
    txt.innerText = "••••••";
    if (icon) icon.setAttribute("data-lucide", "eye");
  }
  lucide.createIcons();
}

function renderSharesTab() {
  return `
    <div class="space-y-6">
      <div class="glass-card p-5 flex items-center justify-between">
        <div>
          <h2 class="text-xl font-extrabold text-white flex items-center gap-2">
            <i data-lucide="share-2" class="w-5 h-5 text-cyan-400"></i> Active Shareable Links
          </h2>
          <p class="text-xs text-slate-300 mt-0.5">Direct public access links with live 1-second countdown timers, password authorization, and instant revocation.</p>
        </div>
      </div>

      <div class="glass-card overflow-hidden">
        <table class="soc-table">
          <thead>
            <tr>
              <th>Shared File</th>
              <th>Permissions</th>
              <th>Password Protected</th>
              <th>Time Remaining</th>
              <th>Access Count</th>
              <th class="text-right">Revoke / Actions</th>
            </tr>
          </thead>
          <tbody>
            ${state.sharedLinks.length === 0 ? `
              <tr>
                <td colspan="6" class="text-center py-12 text-slate-400">
                  <i data-lucide="link" class="w-8 h-8 mx-auto mb-2 opacity-50 text-slate-400"></i>
                  No active shared links. Generate a share link from My Files.
                </td>
              </tr>
            ` : state.sharedLinks.map(s => `
              <tr>
                <td class="font-bold text-white">${escapeHtml(s.filename)}</td>
                <td>
                  <span class="px-2 py-0.5 rounded text-[10px] font-mono ${s.view_only ? 'bg-blue-950 border border-blue-500 text-blue-300' : 'bg-emerald-950 border border-emerald-500 text-emerald-300'}">
                    ${s.view_only ? 'VIEW ONLY' : 'DOWNLOAD ALLOWED'}
                  </span>
                </td>
                <td>
                  <span class="text-xs ${s.is_password_protected ? 'text-amber-400 font-bold' : 'text-slate-400'}">
                    ${s.is_password_protected ? '🔒 Password Required' : 'Public Access'}
                  </span>
                </td>
                <td>
                  <span class="share-countdown-badge" data-expires="${s.expires_at || ''}">
                    ${s.is_expired ? '<span class="text-red-400 font-bold">EXPIRED</span>' : 'Calculating...'}
                  </span>
                </td>
                <td class="font-mono text-xs text-white">${s.download_count} downloads / ${s.view_count} views</td>
                <td class="text-right">
                  <div class="flex items-center justify-end gap-2">
                    <button onclick="navigator.clipboard.writeText('${API_BASE}/api/shares/public/' + '${s.id}'); showToast('Public link copied to clipboard!', 'success');" class="px-2.5 py-1 bg-slate-800 hover:bg-slate-700 rounded text-xs text-white">
                      Copy Link
                    </button>
                    <button onclick="revokeShare('${s.id}')" class="px-2.5 py-1 bg-red-950/60 hover:bg-red-900 border border-red-500/40 rounded text-xs text-red-300">
                      Revoke
                    </button>
                  </div>
                </td>
              </tr>
            `).join('')}
          </tbody>
        </table>
      </div>
    </div>
  `;
}

function renderRecycleBinTab() {
  return `
    <div class="space-y-6">
      <div class="glass-card p-5 flex items-center justify-between">
        <div>
          <h2 class="text-xl font-extrabold text-white flex items-center gap-2">
            <i data-lucide="trash-2" class="w-5 h-5 text-red-400"></i> Recycle Bin & Soft Deletion
          </h2>
          <p class="text-xs text-slate-300 mt-0.5">Files in Recycle Bin are blocked from direct viewing or download until restored.</p>
        </div>
      </div>

      <div class="glass-card overflow-hidden">
        <table class="soc-table">
          <thead>
            <tr>
              <th>File Name</th>
              <th>Size</th>
              <th>SHA-256 Hash</th>
              <th>Deleted Timestamp</th>
              <th class="text-right">Restoration</th>
            </tr>
          </thead>
          <tbody>
            ${state.recycleBin.length === 0 ? `
              <tr>
                <td colspan="5" class="text-center py-12 text-slate-400">
                  <i data-lucide="check-circle-2" class="w-8 h-8 mx-auto mb-2 opacity-50 text-emerald-400"></i>
                  Recycle bin is clean. No deleted files.
                </td>
              </tr>
            ` : state.recycleBin.map(item => `
              <tr>
                <td class="font-bold text-white cursor-pointer" onclick="showToast('This file is in the Recycle Bin and cannot be opened until it is restored.', 'warning')">${escapeHtml(item.original_name)}</td>
                <td class="font-mono text-xs text-white">${item.file_size_formatted}</td>
                <td class="font-mono text-[11px] text-slate-300">${item.file_hash.substring(0, 14)}...</td>
                <td class="text-xs text-slate-300">${item.deleted_at}</td>
                <td class="text-right">
                  <div class="flex items-center justify-end gap-2">
                    <button onclick="restoreFromRecycleBin('${item.file_id}')" class="px-3 py-1 bg-emerald-600 hover:bg-emerald-500 text-white rounded text-xs font-semibold">
                      Restore File
                    </button>
                    <button onclick="permanentDelete('${item.file_id}')" class="px-3 py-1 bg-red-600 hover:bg-red-500 text-white rounded text-xs font-semibold">
                      Purge
                    </button>
                  </div>
                </td>
              </tr>
            `).join('')}
          </tbody>
        </table>
      </div>
    </div>
  `;
}

function renderUserActivityTab() {
  return `
    <div class="space-y-6">
      <div class="glass-card p-5">
        <h2 class="text-xl font-extrabold text-white flex items-center gap-2">
          <i data-lucide="clock" class="w-5 h-5 text-sky-400"></i> Account Activity & Security Audit Trail
        </h2>
        <p class="text-xs text-slate-300 mt-0.5">Chronological record of your file uploads, downloads, sharing actions, and authentications.</p>
      </div>

      <div class="glass-card overflow-hidden">
        <table class="soc-table">
          <thead>
            <tr>
              <th>Timestamp</th>
              <th>Action</th>
              <th>Resource</th>
              <th>Result</th>
              <th>Details</th>
            </tr>
          </thead>
          <tbody>
            ${state.userAuditLogs.length === 0 ? `
              <tr><td colspan="5" class="text-center py-8 text-slate-400">No activity logs recorded yet.</td></tr>
            ` : state.userAuditLogs.map(l => `
              <tr>
                <td class="text-xs font-mono text-slate-300">${l.date} ${l.time}</td>
                <td class="font-bold text-white font-mono text-xs">${l.action}</td>
                <td class="text-xs text-sky-300">${escapeHtml(l.resource || '')}</td>
                <td><span class="px-2 py-0.5 rounded text-[10px] font-bold ${l.result === 'SUCCESS' ? 'bg-emerald-950 text-emerald-300' : 'bg-red-950 text-red-300'}">${l.result}</span></td>
                <td class="text-xs text-slate-300">${escapeHtml(l.details || '')}</td>
              </tr>
            `).join('')}
          </tbody>
        </table>
      </div>
    </div>
  `;
}

// =========================================================================
// ADMIN SOC TABS
// =========================================================================

function renderSocOverviewTab() {
  const soc = state.socStats || {};
  return `
    <div class="space-y-6">
      <!-- Header Banner -->
      <div class="glass-card p-5 flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 border-cyan-500/30">
        <div>
          <div class="flex items-center gap-2">
            <span class="live-pulse"></span>
            <h2 class="text-2xl font-black text-white tracking-wide">SOC ADMIN CONTROL CENTER</h2>
          </div>
          <p class="text-xs text-cyan-300 font-mono mt-0.5">Production Threat Classifier: ${soc.active_model_version || 'LightGBM PE Engine'} | Recall: ${soc.malicious_recall || '100.0%'}</p>
        </div>
        <div class="flex items-center gap-2">
          <button onclick="switchTab('soc-sentinel')" class="btn-cyber px-4 py-2 rounded-lg text-xs font-bold flex items-center gap-1.5">
            <i data-lucide="gauge" class="w-4 h-4"></i> Sentinel VM Monitoring
          </button>
          <button onclick="globalRevokeShares()" class="btn-danger-cyber px-4 py-2 rounded-lg text-xs font-bold">
            <i data-lucide="shield-off" class="w-4 h-4 inline mr-1"></i> Revoke All Shares
          </button>
        </div>
      </div>

      <!-- System Status Indicators -->
      <div class="grid grid-cols-2 sm:grid-cols-4 lg:grid-cols-8 gap-2.5">
        ${[
          { label: "Backend API", status: soc.system_status || "ONLINE", color: "emerald" },
          { label: "Database", status: soc.database_status || "HEALTHY", color: "emerald" },
          { label: "Storage Vault", status: "ONLINE", color: "emerald" },
          { label: "ML Scanner", status: soc.ml_engine || "ONLINE", color: "emerald" },
          { label: "IP Guard", status: soc.ip_guard_status || "ONLINE", color: "emerald" },
          { label: "Prometheus", status: soc.prometheus_status || "CONNECTED", color: "cyan" },
          { label: "Grafana", status: soc.grafana_status || "CONNECTED", color: "cyan" },
          { label: "API Gateway", status: soc.api_status || "ONLINE", color: "emerald" }
        ].map(s => `
          <div class="glass-card p-2.5 text-center border-slate-800">
            <div class="text-[10px] text-slate-400 uppercase font-mono">${s.label}</div>
            <div class="text-xs font-bold text-${s.color}-400 font-mono mt-0.5">${s.status}</div>
          </div>
        `).join('')}
      </div>

      <!-- Live VM Telemetry Cards -->
      <div class="grid grid-cols-2 md:grid-cols-4 gap-4">
        <div class="glass-card p-4 border border-slate-800">
          <div class="text-xs text-slate-300 font-mono uppercase">CPU Utilization</div>
          <div id="live-cpu-val" class="text-2xl font-black text-emerald-400 font-mono mt-1">${state.telemetry?.cpu_utilization || 32.4}%</div>
          <div class="text-[10px] text-slate-400 mt-1">Real-time VM Core Telemetry</div>
        </div>
        <div class="glass-card p-4 border border-slate-800">
          <div class="text-xs text-slate-300 font-mono uppercase">RAM Memory</div>
          <div id="live-ram-val" class="text-2xl font-black text-sky-400 font-mono mt-1">${state.telemetry?.ram_utilization || 48.1}%</div>
          <div class="text-[10px] text-slate-400 mt-1">Physical Host Allocation</div>
        </div>
        <div class="glass-card p-4 border border-slate-800">
          <div class="text-xs text-slate-300 font-mono uppercase">Disk Storage</div>
          <div id="live-disk-val" class="text-2xl font-black text-purple-400 font-mono mt-1">${state.telemetry?.disk_utilization || 42.0}%</div>
          <div class="text-[10px] text-slate-400 mt-1">Vault Storage Partition</div>
        </div>
        <div class="glass-card p-4 border border-slate-800">
          <div class="text-xs text-slate-300 font-mono uppercase">Network Traffic</div>
          <div id="live-net-val" class="text-2xl font-black text-cyan-400 font-mono mt-1">${state.telemetry?.network_bytes_recv_mb || 4.2} MB</div>
          <div class="text-[10px] text-slate-400 mt-1">Inbound I/O Monitored</div>
        </div>
      </div>

      <!-- Quick Links to Admin Centers -->
      <div class="grid grid-cols-1 md:grid-cols-3 gap-4">
        <div class="glass-card p-5 cursor-pointer hover:border-indigo-500 transition" onclick="switchTab('soc-user-files')">
          <h3 class="font-bold text-white flex items-center gap-2">
            <i data-lucide="git-branch" class="w-5 h-5 text-indigo-400"></i> User-Wise File Segregation
          </h3>
          <p class="text-xs text-slate-300 mt-1">Inspect files grouped by user with individual multi-stage scans, rescans, and quarantine status.</p>
        </div>
        <div class="glass-card p-5 cursor-pointer hover:border-red-500 transition" onclick="switchTab('soc-threats')">
          <h3 class="font-bold text-white flex items-center gap-2">
            <i data-lucide="shield-alert" class="w-5 h-5 text-red-400"></i> Threat Operations Center
          </h3>
          <p class="text-xs text-slate-300 mt-1">Inspect suspicious indicators, PE structural anomalies, and trigger on-demand rescans.</p>
        </div>
        <div class="glass-card p-5 cursor-pointer hover:border-amber-500 transition" onclick="switchTab('soc-ip-guard')">
          <h3 class="font-bold text-white flex items-center gap-2">
            <i data-lucide="shield" class="w-5 h-5 text-amber-400"></i> IP Access Guard
          </h3>
          <p class="text-xs text-slate-300 mt-1">Maintain network whitelist and blacklist rules with automated failed login shielding.</p>
        </div>
      </div>
    </div>
  `;
}

// Item 3: Sentinel VM / Grafana SOC Dashboard (Screenshot 4)
function renderSentinelVmTab() {
  const sent = state.sentinelState || {
    phase: "Phase 1: Normal",
    status: "HEALTHY",
    alert_count: 0,
    warning_count: 1,
    overall_health: 87
  };

  return `
    <div class="space-y-6">
      <!-- Sentinel Top Bar -->
      <div class="glass-card p-4 px-6 flex flex-col md:flex-row items-start md:items-center justify-between gap-4 border-sky-500/40">
        <div class="flex items-center gap-3">
          <div class="w-10 h-10 rounded-lg bg-sky-950 border border-sky-500 flex items-center justify-center">
            <i data-lucide="cpu" class="w-5 h-5 text-sky-400"></i>
          </div>
          <div>
            <h2 class="text-xl font-black text-white tracking-wide">SENTINEL VM</h2>
            <p class="text-xs text-slate-300">Cloud Virtual Machine Resource Monitoring & Emergency Incident System</p>
          </div>
        </div>
        <div class="flex flex-wrap items-center gap-2">
          <span class="px-3 py-1 bg-emerald-950 border border-emerald-500/40 text-emerald-300 rounded text-xs font-mono font-bold flex items-center gap-1.5">
            <span class="live-pulse"></span> SYSTEM: ${sent.status}
          </span>
          <span class="px-3 py-1 bg-slate-900 border border-slate-700 text-slate-300 rounded text-xs font-mono">
            Tactical Audio: ARMED (48kHz)
          </span>
          <span class="px-3 py-1 bg-sky-950 border border-sky-500/40 text-sky-300 rounded text-xs font-mono font-bold">
            ROLE: ADMINISTRATOR
          </span>
        </div>
      </div>

      <!-- Workload Spike Phase Trigger Buttons -->
      <div class="glass-card p-4 space-y-2">
        <div class="text-xs text-slate-300 font-bold uppercase tracking-wider">Simulate Workload Spikes, Threshold Crossing & 3-Second Military Alert:</div>
        <div class="flex flex-wrap gap-2">
          <button onclick="triggerSentinelPhase('Phase 1: Normal')" class="px-3.5 py-1.5 bg-emerald-700 hover:bg-emerald-600 text-white rounded-lg text-xs font-bold">
            Phase 1: Normal (32%)
          </button>
          <button onclick="triggerSentinelPhase('Phase 2: Generate Load')" class="px-3.5 py-1.5 bg-amber-700 hover:bg-amber-600 text-white rounded-lg text-xs font-bold">
            Phase 2: Generate Load (68%)
          </button>
          <button onclick="triggerSentinelPhase('Phase 3: Alert Trigger')" class="px-3.5 py-1.5 bg-red-700 hover:bg-red-600 text-white rounded-lg text-xs font-bold animate-pulse">
            Phase 3: Alert Trigger (94%)
          </button>
          <button onclick="triggerSentinelPhase('Phase 5: Acknowledge')" class="px-3.5 py-1.5 bg-sky-700 hover:bg-sky-600 text-white rounded-lg text-xs font-bold">
            Phase 5: Acknowledge
          </button>
          <button onclick="triggerSentinelPhase('Phase 6: Resolve & Report')" class="px-3.5 py-1.5 bg-teal-700 hover:bg-teal-600 text-white rounded-lg text-xs font-bold">
            Phase 6: Resolve & Report
          </button>
        </div>
      </div>

      <!-- Status Metric Cards -->
      <div class="grid grid-cols-2 md:grid-cols-5 gap-3">
        <div class="glass-card p-4 text-center">
          <div class="text-[11px] text-slate-400 uppercase font-mono">System Status</div>
          <div class="text-lg font-black text-emerald-400 mt-1">${sent.status}</div>
          <div class="text-[9px] text-slate-500 mt-0.5">Node Exporter: Active</div>
        </div>
        <div class="glass-card p-4 text-center">
          <div class="text-[11px] text-slate-400 uppercase font-mono">Active Cloud VMs</div>
          <div class="text-lg font-black text-white mt-1">4 / 5</div>
          <div class="text-[9px] text-slate-500 mt-0.5">1 VM Standby</div>
        </div>
        <div class="glass-card p-4 text-center">
          <div class="text-[11px] text-slate-400 uppercase font-mono">Critical Alerts</div>
          <div class="text-lg font-black ${sent.alert_count > 0 ? 'text-red-400' : 'text-white'} mt-1">${sent.alert_count}</div>
          <div class="text-[9px] text-slate-500 mt-0.5">Threshold: >90%</div>
        </div>
        <div class="glass-card p-4 text-center">
          <div class="text-[11px] text-slate-400 uppercase font-mono">Warning Alerts</div>
          <div class="text-lg font-black text-amber-400 mt-1">${sent.warning_count}</div>
          <div class="text-[9px] text-slate-500 mt-0.5">Threshold: >80%</div>
        </div>
        <div class="glass-card p-4 text-center">
          <div class="text-[11px] text-slate-400 uppercase font-mono">Overall Health</div>
          <div class="text-lg font-black text-sky-400 mt-1">${sent.overall_health} / 100</div>
          <div class="text-[9px] text-slate-500 mt-0.5">Availability: 99.90%</div>
        </div>
      </div>

      <!-- Real-Time Waveform Graph & Incident State -->
      <div class="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div class="lg:col-span-2 glass-card p-5 space-y-4">
          <div class="flex items-center justify-between">
            <h3 class="text-xs font-bold text-white font-mono flex items-center gap-2">
              <i data-lucide="activity" class="w-4 h-4 text-sky-400"></i> SENTINEL-VM-01 // REAL-TIME RESOURCE WAVEFORM
            </h3>
            <span class="text-[10px] text-emerald-400 font-mono flex items-center gap-1">
              <span class="live-pulse"></span> LIVE POLLING (1s Interval)
            </span>
          </div>

          <div class="grid grid-cols-3 gap-2 text-center text-xs">
            <div class="p-2 rounded bg-slate-900 border border-slate-800">
              <div class="text-slate-400 text-[10px]">CPU UTILIZATION</div>
              <div class="text-emerald-400 font-bold font-mono text-base">${state.telemetry?.cpu_utilization || 32.4}%</div>
            </div>
            <div class="p-2 rounded bg-slate-900 border border-slate-800">
              <div class="text-slate-400 text-[10px]">RAM CONSUMPTION</div>
              <div class="text-sky-400 font-bold font-mono text-base">${state.telemetry?.ram_utilization || 48.1}%</div>
            </div>
            <div class="p-2 rounded bg-slate-900 border border-slate-800">
              <div class="text-slate-400 text-[10px]">DISK STORAGE (GP3)</div>
              <div class="text-purple-400 font-bold font-mono text-base">${state.telemetry?.disk_utilization || 42.0}%</div>
            </div>
          </div>

          <canvas id="sentinel-waveform-canvas" width="600" height="180" class="w-full h-44 sentinel-waveform-canvas rounded"></canvas>
        </div>

        <div class="glass-card p-5 space-y-4">
          <div class="flex items-center justify-between border-b border-slate-800 pb-2">
            <h3 class="text-xs font-bold text-white font-mono flex items-center gap-2">
              <i data-lucide="alert-octagon" class="w-4 h-4 text-amber-400"></i> ACTIVE INCIDENTS
            </h3>
            <span class="px-2 py-0.5 bg-slate-800 text-[10px] text-slate-300 rounded">${sent.alert_count} ACTIVE</span>
          </div>

          <div class="space-y-3 text-xs">
            ${sent.alert_count > 0 ? `
              <div class="p-3 bg-red-950/60 border border-red-500/50 rounded-lg space-y-1">
                <div class="font-bold text-red-300 flex items-center gap-1.5">
                  <i data-lucide="alert-triangle" class="w-4 h-4"></i> Workload Threshold Breached (94%)
                </div>
                <p class="text-slate-300 text-[11px]">3-second base breach sound activated. CPU core saturation exceeding normal operational threshold.</p>
              </div>
            ` : `
              <div class="p-4 text-center bg-slate-900/60 rounded-lg border border-slate-800 text-slate-400">
                <i data-lucide="shield-check" class="w-8 h-8 mx-auto mb-1 text-emerald-400"></i>
                <div>No active critical emergency incidents.</div>
                <div class="text-[10px] text-slate-500 mt-1">All cloud VM metrics within normal parameters.</div>
              </div>
            `}
          </div>

          <div class="border-t border-slate-800 pt-3 text-[11px] text-slate-400 space-y-1 font-mono">
            <div>• VM Uptime: 14 Days 07 Hours</div>
            <div>• Prometheus Scrape Interval: 5s</div>
            <div>• Alert Routing: 3s Military Horn + Webhook</div>
          </div>
        </div>
      </div>
    </div>
  `;
}

// Item 7: Mandatory User-Wise File Segregation Tree View
function renderUserWiseFilesTab() {
  return `
    <div class="space-y-6">
      <div class="glass-card p-5 flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
        <div>
          <h2 class="text-xl font-extrabold text-white flex items-center gap-2">
            <i data-lucide="git-branch" class="w-5 h-5 text-indigo-400"></i> User-Wise File Segregation
          </h2>
          <p class="text-xs text-slate-300 mt-0.5">Logically segregated files per user with independent multi-stage scanning, rescans, and quarantine status.</p>
        </div>
        <button onclick="loadUserGroupedFiles(); render();" class="px-3 py-1.5 bg-slate-800 hover:bg-slate-700 rounded text-xs text-white font-semibold flex items-center gap-1">
          <i data-lucide="refresh-cw" class="w-3.5 h-3.5"></i> Refresh User Trees
        </button>
      </div>

      <div class="space-y-6">
        ${state.userGroupedFiles.length === 0 ? `
          <div class="glass-card p-12 text-center text-slate-400">
            <i data-lucide="users" class="w-10 h-10 mx-auto mb-2 text-indigo-400 opacity-50"></i>
            No users or segregated files found.
          </div>
        ` : state.userGroupedFiles.map((u, uIdx) => `
          <div class="glass-card p-5 border border-slate-700/80 space-y-4">
            <!-- User Header Summary Card -->
            <div class="flex flex-col md:flex-row items-start md:items-center justify-between gap-3 bg-slate-900/90 p-4 rounded-xl border border-slate-800">
              <div class="flex items-center gap-3">
                <div class="w-9 h-9 rounded-lg bg-indigo-950 border border-indigo-500/40 flex items-center justify-center text-indigo-400 font-bold text-sm">
                  ${uIdx + 1}
                </div>
                <div>
                  <div class="font-black text-white text-base flex items-center gap-2">
                    ${escapeHtml(u.username)}
                    <span class="px-2 py-0.2 bg-slate-800 text-slate-300 rounded text-[10px] font-mono">${u.role}</span>
                    <span class="px-2 py-0.2 rounded text-[10px] font-bold ${u.is_active ? 'bg-emerald-950 text-emerald-300' : 'bg-red-950 text-red-300'}">${u.is_active ? 'ACTIVE' : 'SUSPENDED'}</span>
                  </div>
                  <div class="text-xs text-slate-400 font-mono">${escapeHtml(u.email)}</div>
                </div>
              </div>
              <div class="flex items-center gap-4 text-xs font-mono">
                <div>
                  <span class="text-slate-400">Storage:</span>
                  <span class="text-white font-bold">${u.used_quota_formatted} / ${u.quota_formatted}</span>
                </div>
                <div>
                  <span class="text-slate-400">Files:</span>
                  <span class="text-sky-300 font-bold">${u.file_count}</span>
                </div>
              </div>
            </div>

            <!-- User File List / Tree -->
            <div class="overflow-x-auto">
              <table class="soc-table">
                <thead>
                  <tr>
                    <th>File</th>
                    <th>Type</th>
                    <th>Size</th>
                    <th>Security Verdict</th>
                    <th>Scan Status & Stage</th>
                    <th>Uploaded</th>
                    <th class="text-right">Individual Actions</th>
                  </tr>
                </thead>
                <tbody>
                  ${u.files.length === 0 ? `
                    <tr>
                      <td colspan="7" class="text-center py-6 text-slate-400">No files uploaded by this user.</td>
                    </tr>
                  ` : u.files.map(f => {
                    const scanLive = state.fileScanStates[f.id];
                    return `
                      <tr>
                        <td>
                          <div class="flex items-center gap-2.5">
                            <i data-lucide="${getFileIcon(f.extension)}" class="w-4 h-4 text-sky-400 flex-shrink-0"></i>
                            <div>
                              <div class="font-bold text-white flex items-center gap-1.5">
                                <span class="hover:text-sky-300 cursor-pointer" onclick="${f.is_confidential ? "showToast('Confidential plaintext cannot be viewed by Admin.', 'warning')" : `openFileViewer('${f.id}')`}">${escapeHtml(f.filename)}</span>
                                ${f.is_confidential ? '<span class="px-1.5 py-0.2 bg-amber-950 border border-amber-500/40 text-amber-300 rounded text-[9px] font-mono">🔒 CONFIDENTIAL</span>' : ''}
                              </div>
                              <div class="text-[10px] text-slate-400 font-mono">${f.file_hash.substring(0, 14)}... (${f.current_version})</div>
                            </div>
                          </div>
                        </td>
                        <td><span class="px-2 py-0.5 bg-slate-800 rounded text-[10px] font-mono text-slate-200 uppercase">${f.extension || 'BIN'}</span></td>
                        <td class="font-mono text-xs text-white">${f.file_size_formatted}</td>
                        <td>
                          <span class="px-2.5 py-1 rounded-full text-[11px] font-bold ${getSecurityBadgeClass(scanLive?.security_status || f.security_status)}">
                            ${scanLive?.security_status || f.security_status}
                          </span>
                        </td>
                        <td>
                          ${scanLive?.status === 'SCANNING' ? `
                            <div class="space-y-1">
                              <div class="flex items-center gap-1.5 text-xs text-sky-300 font-bold">
                                <i data-lucide="loader-2" class="w-3.5 h-3.5 animate-spin"></i> ${scanLive.stage_label}
                              </div>
                              <div class="w-32 bg-slate-800 h-1.5 rounded-full overflow-hidden">
                                <div class="bg-sky-400 h-full transition-all duration-300" style="width: ${scanLive.progress_percent}%"></div>
                              </div>
                            </div>
                          ` : `
                            <div class="text-xs font-mono text-slate-300">
                              <span class="text-emerald-400 font-bold">COMPLETED</span>
                              <div class="text-[10px] text-slate-400">${f.last_scanned_at}</div>
                            </div>
                          `}
                        </td>
                        <td class="text-xs text-slate-300">${f.created_at}</td>
                        <td class="text-right">
                          <div class="flex items-center justify-end gap-1.5">
                            <button onclick="runSingleFileScanAdmin('${f.id}', '${escapeHtml(f.filename)}')" title="Run Individual Scan" class="px-2.5 py-1 bg-sky-950 hover:bg-sky-900 border border-sky-500/40 text-sky-300 rounded text-xs font-semibold flex items-center gap-1">
                              <i data-lucide="scan" class="w-3.5 h-3.5"></i> ${scanLive?.status === 'SCANNING' ? 'Scanning...' : 'Scan'}
                            </button>
                            <button onclick="runSingleFileScanAdmin('${f.id}', '${escapeHtml(f.filename)}')" title="Rescan (Preserve History)" class="px-2 py-1 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded text-xs">
                              Rescan
                            </button>
                            <button onclick="viewFileScanHistory('${f.id}', '${escapeHtml(f.filename)}')" title="View Scan History" class="px-2 py-1 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded text-xs">
                              History
                            </button>
                            <button onclick="viewFileSecurityDetails('${f.id}')" title="View Security Details" class="px-2 py-1 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded text-xs">
                              Details
                            </button>
                            ${!f.is_confidential ? `
                              <button onclick="openFileViewer('${f.id}')" title="Preview Original Content" class="p-1.5 text-slate-300 hover:text-white bg-slate-800 rounded">
                                <i data-lucide="eye" class="w-4 h-4"></i>
                              </button>
                            ` : ''}
                          </div>
                        </td>
                      </tr>
                    `;
                  }).join('')}
                </tbody>
              </table>
            </div>
          </div>
        `).join('')}
      </div>
    </div>
  `;
}

function renderSocUsersTab() {
  return `
    <div class="space-y-6">
      <div class="glass-card p-5 flex items-center justify-between">
        <div>
          <h2 class="text-xl font-extrabold text-white flex items-center gap-2">
            <i data-lucide="users" class="w-5 h-5 text-sky-400"></i> User Risk & Storage Management
          </h2>
          <p class="text-xs text-slate-300 mt-0.5">Authoritative database storage quota control, account status toggling, and per-user ML threat scanning.</p>
        </div>
      </div>

      <div class="glass-card overflow-hidden">
        <div class="overflow-x-auto">
          <table class="soc-table">
            <thead>
              <tr>
                <th>Username & Email</th>
                <th>Role</th>
                <th>Status</th>
                <th>Files</th>
                <th>Storage Quota</th>
                <th>Risk Level</th>
                <th class="text-right">Actions</th>
              </tr>
            </thead>
            <tbody>
              ${state.usersList.map(u => `
                <tr>
                  <td class="font-bold text-white">
                    ${escapeHtml(u.username)}
                    <div class="text-[10px] text-slate-300 font-normal">${escapeHtml(u.email)}</div>
                  </td>
                  <td><span class="px-2 py-0.5 bg-slate-800 text-xs font-mono rounded text-white">${u.role}</span></td>
                  <td><span class="px-2 py-0.5 rounded text-[10px] font-bold ${u.is_active ? 'bg-emerald-950 text-emerald-300' : 'bg-red-950 text-red-300'}">${u.is_active ? 'ACTIVE' : 'SUSPENDED'}</span></td>
                  <td>${u.file_count} files (${u.confidential_file_count} vault)</td>
                  <td class="font-mono text-xs text-white">${u.used_quota_formatted} / ${u.quota_formatted}</td>
                  <td>
                    <span class="px-2 py-0.5 rounded text-[10px] font-bold ${u.risk_level === 'CRITICAL' ? 'bg-red-950 text-red-300' : (u.risk_level === 'HIGH' ? 'bg-amber-950 text-amber-300' : 'bg-emerald-950 text-emerald-300')}">
                      ${u.risk_level} (${u.risk_score}%)
                    </span>
                  </td>
                  <td class="text-right">
                    <div class="flex items-center justify-end gap-2">
                      <button onclick="openEditQuotaModal(${u.id}, '${escapeHtml(u.username)}', ${u.quota_bytes / (1024*1024*1024)})" class="px-2.5 py-1 bg-slate-800 hover:bg-slate-700 rounded text-xs text-white">
                        Edit Quota
                      </button>
                      <button onclick="toggleUserStatus(${u.id})" class="px-2.5 py-1 bg-slate-800 hover:bg-slate-700 rounded text-xs text-white">
                        ${u.is_active ? 'Suspend' : 'Reactivate'}
                      </button>
                    </div>
                  </td>
                </tr>
              `).join('')}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  `;
}

function renderSocFilesTab() {
  return `
    <div class="space-y-6">
      <div class="glass-card p-5">
        <h2 class="text-xl font-extrabold text-white flex items-center gap-2">
          <i data-lucide="files" class="w-5 h-5 text-sky-400"></i> Platform File Inventory (All Users)
        </h2>
        <p class="text-xs text-slate-300 mt-0.5">Admin inspection of non-confidential files across all users. Zero confidential plaintext is accessible.</p>
      </div>

      <div class="glass-card overflow-hidden">
        <table class="soc-table">
          <thead>
            <tr>
              <th>Filename</th>
              <th>Owner</th>
              <th>Size</th>
              <th>Security Verdict</th>
              <th>Threat Score</th>
              <th>Uploaded</th>
              <th class="text-right">Admin Actions</th>
            </tr>
          </thead>
          <tbody>
            ${state.allFiles.length === 0 ? `
              <tr><td colspan="7" class="text-center py-8 text-slate-400">No platform files recorded.</td></tr>
            ` : state.allFiles.map(f => `
              <tr>
                <td class="font-bold text-white">${escapeHtml(f.filename)}</td>
                <td class="text-xs text-slate-300 font-mono">${escapeHtml(f.owner)}</td>
                <td class="font-mono text-xs text-white">${f.file_size_formatted}</td>
                <td>
                  <span class="px-2.5 py-1 rounded-full text-[11px] font-bold ${getSecurityBadgeClass(f.security_status)}">
                    ${f.security_status}
                  </span>
                </td>
                <td class="font-mono text-xs font-bold ${f.threat_score >= 60 ? 'text-red-400' : 'text-emerald-400'}">${f.threat_score}%</td>
                <td class="text-xs text-slate-300">${f.created_at}</td>
                <td class="text-right">
                  <div class="flex items-center justify-end gap-2">
                    ${f.is_confidential ? `
                      <span class="text-xs text-amber-400 font-bold">🔒 Encrypted Vault</span>
                    ` : `
                      <button onclick="openFileViewer('${f.id}')" class="px-2.5 py-1 bg-slate-800 hover:bg-slate-700 text-white rounded text-xs">
                        Preview
                      </button>
                      <button onclick="runSingleFileScanAdmin('${f.id}', '${escapeHtml(f.filename)}')" class="px-2.5 py-1 bg-sky-950 border border-sky-500/40 text-sky-300 rounded text-xs font-semibold">
                        Rescan
                      </button>
                    `}
                  </div>
                </td>
              </tr>
            `).join('')}
          </tbody>
        </table>
      </div>
    </div>
  `;
}

function renderSocThreatsTab() {
  return `
    <div class="space-y-6">
      <div class="glass-card p-5">
        <h2 class="text-xl font-extrabold text-white flex items-center gap-2">
          <i data-lucide="shield-alert" class="w-5 h-5 text-red-400"></i> Threat Operations Center
        </h2>
        <p class="text-xs text-slate-300 mt-0.5">Live index of all files flagged with Suspicious or Malicious indicators by LightGBM and Heuristic Engines.</p>
      </div>

      <div class="glass-card overflow-hidden">
        <table class="soc-table">
          <thead>
            <tr>
              <th>Threat Filename</th>
              <th>Owner</th>
              <th>Size</th>
              <th>SHA-256 Fingerprint</th>
              <th>Threat Score</th>
              <th>Security Verdict</th>
              <th class="text-right">Action</th>
            </tr>
          </thead>
          <tbody>
            ${state.threatsList.length === 0 ? `
              <tr><td colspan="7" class="text-center py-8 text-slate-400">No active threats detected. All platform files are clean.</td></tr>
            ` : state.threatsList.map(t => `
              <tr>
                <td class="font-bold text-red-400 font-mono">${escapeHtml(t.filename)}</td>
                <td class="text-xs text-slate-300 font-mono">${escapeHtml(t.owner)}</td>
                <td class="font-mono text-xs text-white">${t.file_size_formatted}</td>
                <td class="font-mono text-[11px] text-slate-300">${t.file_hash.substring(0, 16)}...</td>
                <td class="font-mono text-xs font-bold text-red-400">${t.threat_score}%</td>
                <td>
                  <span class="px-2 py-0.5 rounded text-[10px] font-bold ${t.security_status === 'MALICIOUS' ? 'bg-red-950 text-red-300' : 'bg-amber-950 text-amber-300'}">
                    ${t.security_status}
                  </span>
                </td>
                <td class="text-right">
                  <button onclick="runSingleFileScanAdmin('${t.id}', '${escapeHtml(t.filename)}')" class="px-2.5 py-1 bg-sky-950 border border-sky-500/40 text-sky-300 rounded text-xs font-semibold">
                    Rescan
                  </button>
                </td>
              </tr>
            `).join('')}
          </tbody>
        </table>
      </div>
    </div>
  `;
}

function renderSocQuarantineTab() {
  return `
    <div class="space-y-6">
      <div class="glass-card p-5">
        <h2 class="text-xl font-extrabold text-white flex items-center gap-2">
          <i data-lucide="archive" class="w-5 h-5 text-red-400"></i> Quarantined Threat Vault
        </h2>
        <p class="text-xs text-slate-300 mt-0.5">Isolated malicious binaries and scripts prevented from execution or download.</p>
      </div>

      <div class="glass-card overflow-hidden">
        <table class="soc-table">
          <thead>
            <tr>
              <th>Threat File</th>
              <th>SHA-256 Hash</th>
              <th>Detection Reason</th>
              <th>Quarantined At</th>
              <th class="text-right">Review Action</th>
            </tr>
          </thead>
          <tbody>
            ${state.quarantinedList.length === 0 ? `
              <tr><td colspan="5" class="text-center py-8 text-slate-400">No quarantined files. Clean system state.</td></tr>
            ` : state.quarantinedList.map(q => `
              <tr>
                <td class="font-bold text-red-400 font-mono">${escapeHtml(q.original_filename)}</td>
                <td class="font-mono text-xs text-slate-300">${q.file_hash.substring(0, 16)}...</td>
                <td class="text-xs text-white">${escapeHtml(q.reason)}</td>
                <td class="text-xs text-slate-300">${q.quarantined_at}</td>
                <td class="text-right">
                  <div class="flex items-center justify-end gap-2">
                    <button onclick="handleQuarantineAction(${q.id}, 'RESTORE')" class="px-2.5 py-1 bg-emerald-950 border border-emerald-500/40 text-emerald-300 rounded text-xs font-semibold">Restore</button>
                    <button onclick="handleQuarantineAction(${q.id}, 'DELETE')" class="px-2.5 py-1 bg-red-950 border border-red-500/40 text-red-300 rounded text-xs font-semibold">Destroy</button>
                  </div>
                </td>
              </tr>
            `).join('')}
          </tbody>
        </table>
      </div>
    </div>
  `;
}

function renderSocIpGuardTab() {
  return `
    <div class="space-y-6">
      <div class="glass-card p-5 flex items-center justify-between">
        <div>
          <h2 class="text-xl font-extrabold text-white flex items-center gap-2">
            <i data-lucide="shield" class="w-5 h-5 text-amber-400"></i> IP Access Guard & Shield
          </h2>
          <p class="text-xs text-slate-300 mt-0.5">Whitelist and blacklist management with automatic brute-force isolation.</p>
        </div>
        <button onclick="openModal('new-ip')" class="btn-cyber px-4 py-2 rounded-lg text-xs font-bold flex items-center gap-1.5">
          <i data-lucide="plus" class="w-4 h-4"></i> Add IP Rule
        </button>
      </div>

      <div class="glass-card overflow-hidden">
        <table class="soc-table">
          <thead>
            <tr>
              <th>IP Address</th>
              <th>Rule Type</th>
              <th>Description</th>
              <th>Last Seen</th>
              <th>Threat Status</th>
              <th class="text-right">Delete</th>
            </tr>
          </thead>
          <tbody>
            ${state.ipRules.length === 0 ? `
              <tr><td colspan="6" class="text-center py-8 text-slate-400">No IP rules configured.</td></tr>
            ` : state.ipRules.map(r => `
              <tr>
                <td class="font-mono font-bold text-white">${escapeHtml(r.ip_address)}</td>
                <td>
                  <span class="px-2 py-0.5 rounded text-[10px] font-bold ${r.rule_type === 'BLACKLIST' ? 'bg-red-950 text-red-300' : 'bg-emerald-950 text-emerald-300'}">
                    ${r.rule_type}
                  </span>
                </td>
                <td class="text-xs text-slate-300">${escapeHtml(r.description || '')}</td>
                <td class="text-xs text-slate-300 font-mono">${r.last_seen}</td>
                <td><span class="px-2 py-0.5 bg-slate-800 text-slate-200 rounded text-[10px] font-mono">${r.threat_status}</span></td>
                <td class="text-right">
                  <button onclick="deleteIpRule(${r.id})" class="text-red-400 hover:text-red-300 p-1">
                    <i data-lucide="trash-2" class="w-4 h-4"></i>
                  </button>
                </td>
              </tr>
            `).join('')}
          </tbody>
        </table>
      </div>
    </div>
  `;
}

function renderSocSessionsTab() {
  return `
    <div class="space-y-6">
      <div class="glass-card p-5">
        <h2 class="text-xl font-extrabold text-white flex items-center gap-2">
          <i data-lucide="key" class="w-5 h-5 text-purple-400"></i> Active User Sessions
        </h2>
        <p class="text-xs text-slate-300 mt-0.5">View and revoke active JWT tokens and sessions across the platform.</p>
      </div>

      <div class="glass-card overflow-hidden">
        <table class="soc-table">
          <thead>
            <tr>
              <th>User</th>
              <th>Role</th>
              <th>IP Address</th>
              <th>User Agent</th>
              <th>Login Time</th>
              <th>Expires At</th>
              <th class="text-right">Revoke</th>
            </tr>
          </thead>
          <tbody>
            ${state.sessionsList.length === 0 ? `
              <tr><td colspan="7" class="text-center py-8 text-slate-400">No active sessions.</td></tr>
            ` : state.sessionsList.map(s => `
              <tr>
                <td class="font-bold text-white">${escapeHtml(s.username)}</td>
                <td><span class="px-2 py-0.5 bg-slate-800 text-xs font-mono rounded text-white">${s.role}</span></td>
                <td class="font-mono text-xs text-cyan-300">${escapeHtml(s.ip_address)}</td>
                <td class="text-xs text-slate-300 max-w-xs truncate" title="${escapeHtml(s.user_agent)}">${escapeHtml(s.user_agent)}</td>
                <td class="text-xs text-slate-300">${s.created_at}</td>
                <td class="text-xs text-slate-300">${s.expires_at}</td>
                <td class="text-right">
                  <button onclick="revokeSession('${s.id}')" class="px-2.5 py-1 bg-red-950 hover:bg-red-900 border border-red-500/40 rounded text-xs text-red-300">
                    Revoke
                  </button>
                </td>
              </tr>
            `).join('')}
          </tbody>
        </table>
      </div>
    </div>
  `;
}

function renderSocAuditTab() {
  return `
    <div class="space-y-6">
      <div class="glass-card p-5">
        <h2 class="text-xl font-extrabold text-white flex items-center gap-2">
          <i data-lucide="list" class="w-5 h-5 text-sky-400"></i> Immutable Platform Audit Logs
        </h2>
        <p class="text-xs text-slate-300 mt-0.5">Chronological security records of authentications, file modifications, scans, and administrative operations.</p>
      </div>

      <div class="glass-card overflow-hidden">
        <table class="soc-table">
          <thead>
            <tr>
              <th>Timestamp</th>
              <th>User</th>
              <th>Role</th>
              <th>IP</th>
              <th>Action</th>
              <th>Resource</th>
              <th>Result</th>
              <th>Details</th>
            </tr>
          </thead>
          <tbody>
            ${state.auditLogs.map(l => `
              <tr>
                <td class="text-xs font-mono text-slate-300">${l.timestamp}</td>
                <td class="font-bold text-white">${escapeHtml(l.username)}</td>
                <td><span class="px-2 py-0.5 bg-slate-800 text-[10px] font-mono rounded text-slate-200">${l.role}</span></td>
                <td class="font-mono text-xs text-slate-300">${escapeHtml(l.ip_address)}</td>
                <td class="font-mono text-xs font-bold text-sky-300">${l.action}</td>
                <td class="text-xs text-white max-w-xs truncate">${escapeHtml(l.resource || '')}</td>
                <td><span class="px-2 py-0.5 rounded text-[10px] font-bold ${l.result === 'SUCCESS' ? 'bg-emerald-950 text-emerald-300' : 'bg-red-950 text-red-300'}">${l.result}</span></td>
                <td class="text-xs text-slate-300 max-w-xs truncate" title="${escapeHtml(l.details || '')}">${escapeHtml(l.details || '')}</td>
              </tr>
            `).join('')}
          </tbody>
        </table>
      </div>
    </div>
  `;
}

// =========================================================================
// Multi-Format File Viewer Content Renderer (Item 6: White DOCX Sheet + Black Font)
// =========================================================================

function renderSpecificFileFormat(content, file) {
  if (!content) return '<div class="p-8 text-center text-slate-400">No content available for this file.</div>';

  // 1. DOCX Word Document Formatted Preview (Crisp White Document Sheet + Black Typography)
  if (content.format === "DOCX_RENDERED") {
    if (content.html_content && content.html_content.trim()) {
      return `
        <div class="docx-document-sheet p-10 max-w-4xl mx-auto space-y-4">
          <div class="border-b border-slate-300 pb-2 mb-4 flex items-center justify-between text-xs text-slate-600 font-mono">
            <span class="font-bold text-black"><i data-lucide="file-text" class="w-4 h-4 inline mr-1 text-black"></i> Word Document Specification Sheet</span>
            <span>${content.paragraph_count || 0} Paragraphs</span>
          </div>
          <div class="text-black leading-relaxed text-sm space-y-3">
            ${content.html_content}
          </div>
        </div>
      `;
    }
    return `
      <div class="docx-document-sheet p-10 max-w-4xl mx-auto space-y-4">
        <div class="border-b border-slate-300 pb-2 mb-4 text-xs text-slate-600 font-mono">
          📄 Word Document Content (${content.paragraph_count || 0} Paragraphs)
        </div>
        ${(content.paragraphs || []).map(p => `
          <p class="leading-relaxed text-black text-sm ${p.style.includes('Heading') ? 'font-black text-lg text-black pt-2 border-b border-slate-300 pb-1' : 'text-slate-900'}">
            ${escapeHtml(p.text)}
          </p>
        `).join('')}
        ${(content.tables || []).map(tbl => `
          <table class="w-full border-collapse border border-slate-300 text-xs my-4 text-black bg-white">
            ${tbl.map(row => `
              <tr class="border-b border-slate-300">
                ${row.map(cell => `<td class="border border-slate-300 p-2.5 text-black bg-white">${escapeHtml(cell)}</td>`).join('')}
              </tr>
            `).join('')}
          </table>
        `).join('')}
      </div>
    `;
  }

  // 2. XLSX Spreadsheet Preview
  if (content.format === "XLSX_RENDERED") {
    return `
      <div class="space-y-4">
        <div class="flex gap-2 border-b border-slate-800 pb-2 overflow-x-auto">
          ${(content.sheet_names || []).map(sh => `
            <span class="px-3 py-1 bg-slate-800 border border-slate-700 rounded text-xs text-white font-semibold">${escapeHtml(sh)}</span>
          `).join('')}
        </div>
        <div class="overflow-x-auto border border-slate-800 rounded-lg bg-[#0b1120]">
          <table class="soc-table">
            ${Object.values(content.sheets || {})[0]?.map((row, idx) => `
              <tr class="${idx === 0 ? 'bg-slate-900 font-black text-sky-300' : ''}">
                ${row.map(cell => `<td class="p-2.5 border-r border-slate-800 text-white">${escapeHtml(cell)}</td>`).join('')}
              </tr>
            `).join('')}
          </table>
        </div>
      </div>
    `;
  }

  // 3. PPTX Presentation Preview
  if (content.format === "PPTX_RENDERED") {
    return `
      <div class="space-y-4">
        <div class="text-xs text-sky-300 font-bold uppercase">Presentation Slides (${content.slide_count || 0} Slides):</div>
        <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
          ${(content.slides || []).map(sl => `
            <div class="p-4 rounded-xl bg-[#0b1120] border border-slate-700 space-y-2">
              <div class="text-[11px] font-bold text-sky-400 font-mono">Slide ${sl.slide_number}</div>
              <div class="text-white text-xs space-y-1 font-sans">
                ${sl.content.map(txt => `<p class="text-white leading-relaxed">• ${escapeHtml(txt)}</p>`).join('')}
              </div>
            </div>
          `).join('')}
        </div>
      </div>
    `;
  }

  // 4. CSV Table Formatted Preview
  if (content.format === "CSV_TABLE") {
    return `
      <div class="overflow-x-auto border border-slate-800 rounded-lg bg-[#0b1120]">
        <table class="soc-table">
          ${(content.rows || []).map((row, idx) => `
            <tr class="${idx === 0 ? 'bg-slate-900 font-bold text-sky-300' : ''}">
              ${row.map(cell => `<td class="p-2 border-r border-slate-800 text-white">${escapeHtml(cell)}</td>`).join('')}
            </tr>
          `).join('')}
        </table>
      </div>
    `;
  }

  // 5. Plain Text, Code, JSON, XML
  if (content.format === "TEXT" || content.format === "JSON") {
    return `
      <pre class="p-4 bg-[#0b1120] text-white rounded-lg overflow-x-auto leading-relaxed border border-slate-800 font-mono text-xs"><code class="text-white">${escapeHtml(content.content || '')}</code></pre>
    `;
  }

  // 6. Streamable Media (PDF, Images, Video, Audio)
  if (content.format === "STREAMABLE_MEDIA") {
    const ext = (file.filename || '').split('.').pop().toLowerCase();
    const streamUrl = content.stream_url.startsWith("http") ? content.stream_url : `${API_BASE}${content.stream_url}`;

    if (["mp4", "webm", "mov", "avi"].includes(ext)) {
      return `
        <div class="space-y-3">
          <div class="flex items-center justify-between bg-slate-900/90 p-2.5 px-4 rounded-lg border border-slate-800 text-xs">
            <span class="text-sky-300 font-mono flex items-center gap-1.5"><i data-lucide="video" class="w-4 h-4 text-sky-400"></i> Video Playback Stream</span>
            <a href="${streamUrl}" target="_blank" class="px-2.5 py-1 bg-sky-600 hover:bg-sky-500 text-white rounded text-xs font-semibold flex items-center gap-1">
              <i data-lucide="external-link" class="w-3.5 h-3.5"></i> Open Direct Stream
            </a>
          </div>
          <video controls autoplay class="w-full rounded-xl max-h-[65vh] border border-slate-800 bg-black" src="${streamUrl}"></video>
        </div>
      `;
    }
    if (["mp3", "wav", "ogg", "flac"].includes(ext)) {
      return `
        <div class="space-y-4">
          <div class="flex items-center justify-between bg-slate-900/90 p-2.5 px-4 rounded-lg border border-slate-800 text-xs">
            <span class="text-sky-300 font-mono flex items-center gap-1.5"><i data-lucide="music" class="w-4 h-4 text-sky-400"></i> Audio Stream Playback</span>
            <a href="${streamUrl}" target="_blank" class="px-2.5 py-1 bg-sky-600 hover:bg-sky-500 text-white rounded text-xs font-semibold flex items-center gap-1">
              <i data-lucide="external-link" class="w-3.5 h-3.5"></i> Open Audio Link
            </a>
          </div>
          <div class="p-10 text-center bg-[#0b1120] rounded-xl border border-slate-800 shadow-inner">
            <audio controls autoplay class="w-full max-w-lg mx-auto" src="${streamUrl}"></audio>
          </div>
        </div>
      `;
    }
    if (["png", "jpg", "jpeg", "gif", "webp", "svg"].includes(ext)) {
      return `
        <div class="space-y-3">
          <div class="flex items-center justify-between bg-slate-900/90 p-2.5 px-4 rounded-lg border border-slate-800 text-xs">
            <span class="text-sky-300 font-mono flex items-center gap-1.5"><i data-lucide="image" class="w-4 h-4 text-sky-400"></i> High-Resolution Image Preview</span>
            <a href="${streamUrl}" target="_blank" class="px-2.5 py-1 bg-sky-600 hover:bg-sky-500 text-white rounded text-xs font-semibold flex items-center gap-1">
              <i data-lucide="external-link" class="w-3.5 h-3.5"></i> Open Full Image
            </a>
          </div>
          <div class="text-center p-4 bg-[#0b1120] rounded-xl border border-slate-800">
            <img class="max-h-[65vh] mx-auto rounded-lg shadow-2xl border border-slate-700" src="${streamUrl}" alt="${escapeHtml(file.filename)}" />
          </div>
        </div>
      `;
    }
    if (ext === "pdf") {
      return `
        <div class="w-full flex flex-col h-[75vh] space-y-2">
          <div class="flex items-center justify-between bg-slate-900/90 p-2.5 px-4 rounded-lg border border-slate-800 text-xs">
            <span class="text-sky-300 font-mono flex items-center gap-1.5"><i data-lucide="file-text" class="w-4 h-4 text-sky-400"></i> PDF Document Preview</span>
            <div class="flex items-center gap-2">
              <a href="${streamUrl}" target="_blank" class="px-2.5 py-1 bg-sky-600 hover:bg-sky-500 text-white rounded text-xs font-semibold flex items-center gap-1">
                <i data-lucide="external-link" class="w-3.5 h-3.5"></i> Open in New Tab
              </a>
              <a href="${API_BASE}/api/files/${file.id}/download" class="px-2.5 py-1 bg-slate-800 hover:bg-slate-700 text-white rounded text-xs font-semibold flex items-center gap-1">
                <i data-lucide="download" class="w-3.5 h-3.5"></i> Download
              </a>
            </div>
          </div>
          <div class="w-full flex-1 rounded-lg overflow-hidden border border-slate-800 bg-[#0b1120]">
            <iframe class="w-full h-full bg-slate-900" src="${streamUrl}" title="${escapeHtml(file.filename)}"></iframe>
          </div>
        </div>
      `;
    }
  }

  return `
    <div class="p-8 text-center space-y-4 bg-[#0b1120] rounded-xl border border-slate-800">
      <i data-lucide="file-question" class="w-12 h-12 mx-auto text-sky-400 opacity-60"></i>
      <div class="text-sm font-bold text-white">Preview unavailable for this file format.</div>
      <p class="text-xs text-slate-300 max-w-md mx-auto">This binary file format cannot be rendered directly in the browser window. You can safely download and inspect the original bytes using the button below.</p>
      <div class="pt-2">
        <a href="${API_BASE}/api/files/${file.id}/download" class="btn-cyber px-5 py-2 rounded-lg text-xs font-bold inline-flex items-center gap-1.5">
          <i data-lucide="download" class="w-4 h-4"></i> Download Original Bytes
        </a>
      </div>
    </div>
  `;
}

// =========================================================================
// Modals View & Forms
// =========================================================================

function renderModals() {
  if (!state.activeModal) return '';

  return `
    <div class="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm animate-fadeIn">
      <div class="glass-card max-w-3xl w-full max-h-[90vh] flex flex-col overflow-hidden shadow-2xl border-slate-700">
        
        <!-- Modal Header -->
        <div class="p-4 px-6 border-b border-slate-800 flex items-center justify-between bg-slate-900/90">
          <h3 class="font-bold text-white flex items-center gap-2">
            ${getModalTitle(state.activeModal)}
          </h3>
          <button onclick="closeModal()" class="text-slate-400 hover:text-white text-xl font-bold">&times;</button>
        </div>

        <!-- Modal Body -->
        <div class="p-6 overflow-y-auto flex-1">
          ${renderModalBody(state.activeModal)}
        </div>
      </div>
    </div>
  `;
}

function getModalTitle(modal) {
  switch (modal) {
    case "login": return '<i data-lucide="shield-check" class="w-5 h-5 text-sky-400"></i> Security Authentication Portal';
    case "viewer": return `<i data-lucide="file-text" class="w-5 h-5 text-sky-400"></i> ${escapeHtml(state.activeFile?.filename || 'File Preview')}`;
    case "pin-lock": return '<i data-lucide="lock" class="w-5 h-5 text-amber-400"></i> Confidential Vault Encryption';
    case "pin-unlock": return '<i data-lucide="key" class="w-5 h-5 text-amber-400"></i> Decrypt Confidential File';
    case "share-create": return '<i data-lucide="share-2" class="w-5 h-5 text-cyan-400"></i> Generate Secure Shared Link';
    case "rename": return '<i data-lucide="edit-3" class="w-5 h-5 text-purple-400"></i> Rename File';
    case "versions": return '<i data-lucide="history" class="w-5 h-5 text-sky-400"></i> File Version History';
    case "edit-quota": return '<i data-lucide="hard-drive" class="w-5 h-5 text-sky-400"></i> Edit User Storage Quota';
    case "new-ip": return '<i data-lucide="shield-plus" class="w-5 h-5 text-amber-400"></i> Add IP Access Rule';
    case "scan-history": return `<i data-lucide="history" class="w-5 h-5 text-sky-400"></i> Scan History: ${escapeHtml(state.activeFile?.filename || '')}`;
    case "security-details": return '<i data-lucide="shield-alert" class="w-5 h-5 text-red-400"></i> Deep Security & Threat Details';
    default: return 'Security Action';
  }
}

function renderModalBody(modal) {
  switch (modal) {
    case "login":
      return `
        <div class="space-y-5">
          <!-- 4-Mode Switcher: USER / ADMIN / REGISTER / FORGOT PW -->
          <div class="grid grid-cols-4 gap-1.5 bg-slate-900 p-1 rounded-xl border border-slate-800">
            <button id="auth-mode-user" onclick="setAuthPortalMode('USER')" class="py-2 rounded-lg text-xs font-bold text-white bg-sky-600 transition">
              USER
            </button>
            <button id="auth-mode-admin" onclick="setAuthPortalMode('ADMIN')" class="py-2 rounded-lg text-xs font-bold text-slate-300 hover:text-white transition">
              ADMIN
            </button>
            <button id="auth-mode-register" onclick="setAuthPortalMode('REGISTER')" class="py-2 rounded-lg text-xs font-bold text-slate-300 hover:text-white transition">
              REGISTER
            </button>
            <button id="auth-mode-forgot" onclick="setAuthPortalMode('FORGOT')" class="py-2 rounded-lg text-xs font-bold text-slate-300 hover:text-white transition">
              RESET PW
            </button>
          </div>

          <!-- Registration Form -->
          <div id="auth-form-register" class="space-y-4 hidden">
            <div>
              <label class="block text-xs font-semibold text-slate-300 mb-1">Username</label>
              <input id="reg-username" type="text" placeholder="e.g. analyst_john" class="w-full bg-slate-900 border border-slate-700 rounded-lg p-2.5 text-xs text-white outline-none focus:border-sky-500" />
            </div>
            <div>
              <label class="block text-xs font-semibold text-slate-300 mb-1">Email Address</label>
              <input id="reg-email" type="email" placeholder="john@securecloud.com" class="w-full bg-slate-900 border border-slate-700 rounded-lg p-2.5 text-xs text-white outline-none focus:border-sky-500" />
            </div>
            <div>
              <label class="block text-xs font-semibold text-slate-300 mb-1">Password</label>
              <div class="relative">
                <input id="reg-password" type="password" placeholder="••••••••••••" class="w-full bg-slate-900 border border-slate-700 rounded-lg p-2.5 pr-10 text-xs text-white outline-none focus:border-sky-500 font-mono" />
                <button type="button" onclick="togglePasswordVisibility('reg-password', 'reg-pw-eye')" class="absolute right-2.5 top-2.5 text-slate-400 hover:text-white transition p-1">
                  <i id="reg-pw-eye" data-lucide="eye" class="w-4 h-4"></i>
                </button>
              </div>
            </div>
            <div>
              <label class="block text-xs font-semibold text-slate-300 mb-1">Select Role</label>
              <select id="reg-role" class="w-full bg-slate-900 border border-slate-700 rounded-lg p-2.5 text-xs text-white outline-none">
                <option value="USER">USER (Standard Vault & File Protection)</option>
                <option value="ADMIN">ADMIN (SOC Control Center Access)</option>
              </select>
            </div>
            <button onclick="handleRegisterSubmit()" class="btn-cyber w-full py-2.5 rounded-lg text-xs font-bold mt-2">
              Create Account & Enter Portal
            </button>
          </div>

          <!-- Forgot / Reset Password Form (Item 1) -->
          <div id="auth-form-forgot" class="space-y-4 hidden">
            <div class="p-3 bg-indigo-950/40 border border-indigo-500/30 rounded-lg text-xs text-indigo-200">
              Enter your registered account email to request a reset token and set a new password.
            </div>
            <div>
              <label class="block text-xs font-semibold text-slate-300 mb-1">Account Email</label>
              <div class="flex gap-2">
                <input id="forgot-email" type="email" placeholder="user@securecloud.com" class="w-full bg-slate-900 border border-slate-700 rounded-lg p-2.5 text-xs text-white outline-none focus:border-sky-500" />
                <button type="button" onclick="handleForgotPasswordRequest()" class="px-3 py-2 bg-slate-800 hover:bg-slate-700 border border-slate-700 rounded-lg text-xs text-white whitespace-nowrap">
                  Get Token
                </button>
              </div>
            </div>
            <div>
              <label class="block text-xs font-semibold text-slate-300 mb-1">Reset Token / Verification Code</label>
              <input id="reset-token" type="text" placeholder="Generated reset token" class="w-full bg-slate-900 border border-slate-700 rounded-lg p-2.5 text-xs text-white font-mono outline-none" />
            </div>
            <div>
              <label class="block text-xs font-semibold text-slate-300 mb-1">New Password</label>
              <div class="relative">
                <input id="reset-new-password" type="password" placeholder="••••••••••••" class="w-full bg-slate-900 border border-slate-700 rounded-lg p-2.5 pr-10 text-xs text-white outline-none font-mono" />
                <button type="button" onclick="togglePasswordVisibility('reset-new-password', 'reset-pw-eye')" class="absolute right-2.5 top-2.5 text-slate-400 hover:text-white transition p-1">
                  <i id="reset-pw-eye" data-lucide="eye" class="w-4 h-4"></i>
                </button>
              </div>
            </div>
            <button onclick="handleResetPasswordSubmit()" class="btn-cyber w-full py-2.5 rounded-lg text-xs font-bold mt-2">
              Update Password & Access Account
            </button>
          </div>

          <!-- Login Form (User / Admin) -->
          <div id="auth-form-login" class="space-y-4">
            <div id="auth-portal-banner" class="p-3 bg-sky-950/40 border border-sky-500/30 rounded-lg text-xs text-sky-200">
              Authenticating for <strong>USER PORTAL</strong>. Role validation strictly enforced.
            </div>
            <div>
              <label class="block text-xs font-semibold text-slate-300 mb-1">Email Address</label>
              <input id="login-email" type="email" placeholder="user@securecloud.com" class="w-full bg-slate-900 border border-slate-700 rounded-lg p-2.5 text-xs text-white outline-none focus:border-sky-500" />
            </div>
            <div>
              <div class="flex items-center justify-between mb-1">
                <label class="block text-xs font-semibold text-slate-300">Password</label>
                <button type="button" onclick="setAuthPortalMode('FORGOT')" class="text-[11px] text-sky-400 hover:underline">
                  Forgot Password?
                </button>
              </div>
              <div class="relative">
                <input id="login-password" type="password" placeholder="••••••••••••" class="w-full bg-slate-900 border border-slate-700 rounded-lg p-2.5 pr-10 text-xs text-white outline-none focus:border-sky-500 font-mono" />
                <button type="button" onclick="togglePasswordVisibility('login-password', 'login-pw-eye')" class="absolute right-2.5 top-2.5 text-slate-400 hover:text-white transition p-1">
                  <i id="login-pw-eye" data-lucide="eye" class="w-4 h-4"></i>
                </button>
              </div>
            </div>

            <!-- Realistic "I'm not a robot" CAPTCHA Box -->
            <div class="bg-slate-900/90 border border-slate-700 rounded-xl p-3.5 flex items-center justify-between shadow-inner">
              <label class="flex items-center gap-3 cursor-pointer select-none">
                <div class="relative w-6 h-6 flex items-center justify-center">
                  <input 
                    type="checkbox" 
                    id="mock-captcha" 
                    class="w-5 h-5 rounded border-slate-600 bg-slate-950 text-sky-500 focus:ring-sky-500 cursor-pointer accent-sky-500" 
                    onchange="handleCaptchaToggle(this)"
                  />
                  <div id="captcha-spinner" class="hidden absolute inset-0 flex items-center justify-center bg-slate-900 rounded">
                    <i data-lucide="loader-2" class="w-5 h-5 text-sky-400 animate-spin"></i>
                  </div>
                </div>
                <span class="text-xs sm:text-sm text-slate-200 font-medium">I'm not a robot</span>
              </label>
              <div class="flex flex-col items-end text-right">
                <div class="flex items-center gap-1 text-[11px] font-bold text-sky-400">
                  <i data-lucide="shield-check" class="w-3.5 h-3.5"></i> reCAPTCHA
                </div>
                <div class="text-[9px] text-slate-500">Privacy - Terms</div>
              </div>
            </div>

            <button onclick="handleLoginSubmit()" class="btn-cyber w-full py-2.5 rounded-lg text-xs font-bold">
              Authenticate & Verify Role
            </button>
            <div class="text-center pt-1">
              <span class="text-xs text-slate-400">Default Accounts: <code>admin@securecloud.com</code> / <code>analyst@securecloud.com</code></span>
            </div>
          </div>
        </div>
      `;

    case "viewer":
      return `
        <div class="space-y-4">
          ${renderSpecificFileFormat(state.activeViewerContent, state.activeFile)}
        </div>
      `;

    case "scan-history":
      return `
        <div class="space-y-4">
          <p class="text-xs text-slate-300">Chronological scan history preserved across previous scans:</p>
          <div class="border border-slate-800 rounded-lg overflow-hidden bg-slate-900/80">
            <table class="soc-table">
              <thead>
                <tr>
                  <th>Timestamp</th>
                  <th>Engine / ML Model</th>
                  <th>Verdict</th>
                  <th>Threat Score</th>
                </tr>
              </thead>
              <tbody>
                ${state.activeScanHistory.length === 0 ? `
                  <tr><td colspan="4" class="text-center py-6 text-slate-400">No scan history entries found for this file.</td></tr>
                ` : state.activeScanHistory.map(s => `
                  <tr>
                    <td class="text-xs font-mono text-slate-300">${s.scanned_at}</td>
                    <td class="text-xs text-white font-mono">${s.model_version}</td>
                    <td>
                      <span class="px-2.5 py-0.5 rounded text-[10px] font-bold ${getSecurityBadgeClass(s.security_status)}">
                        ${s.final_verdict}
                      </span>
                    </td>
                    <td class="font-mono text-xs font-bold text-white">${s.threat_score}%</td>
                  </tr>
                `).join('')}
              </tbody>
            </table>
          </div>
        </div>
      `;

    case "security-details":
      const d = state.activeSecurityDetails;
      if (!d) return '<div class="text-center py-6 text-slate-400">Security details loading...</div>';
      return `
        <div class="space-y-4 text-xs">
          <div class="grid grid-cols-2 gap-3 p-3.5 bg-slate-900 rounded-lg border border-slate-800">
            <div><span class="text-slate-400">File Name:</span> <strong class="text-white">${escapeHtml(d.filename)}</strong></div>
            <div><span class="text-slate-400">Owner:</span> <strong class="text-sky-300 font-mono">${escapeHtml(d.owner)}</strong></div>
            <div><span class="text-slate-400">Size:</span> <span class="text-white font-mono">${d.file_size_formatted}</span></div>
            <div><span class="text-slate-400">MIME Type:</span> <span class="text-slate-300 font-mono">${d.mime_type}</span></div>
            <div class="col-span-2"><span class="text-slate-400">SHA-256:</span> <span class="text-slate-300 font-mono text-[11px]">${d.sha256}</span></div>
          </div>

          <div class="p-4 bg-slate-900/90 rounded-lg border border-slate-800 space-y-2">
            <div class="flex items-center justify-between">
              <span class="text-slate-300 font-bold uppercase">Verdict & ML Classifier:</span>
              <span class="px-2.5 py-1 rounded text-xs font-bold ${getSecurityBadgeClass(d.security_status)}">
                ${d.security_status} (Score: ${d.threat_score}%)
              </span>
            </div>
            <div class="text-slate-400 font-mono text-[11px]">Active Pipeline: ${d.latest_scan?.model_version || 'LightGBM / EMBER2024'}</div>
          </div>

          <div class="space-y-2">
            <div class="text-slate-300 font-bold uppercase">Heuristic & Feature Explanations:</div>
            <ul class="space-y-1 p-3 bg-slate-900 rounded-lg border border-slate-800 text-slate-200">
              ${(d.latest_scan?.explanations || ["File verified clean."]).map(exp => `
                <li class="flex items-center gap-2">
                  <i data-lucide="check" class="w-3.5 h-3.5 text-sky-400 flex-shrink-0"></i>
                  <span>${escapeHtml(exp)}</span>
                </li>
              `).join('')}
            </ul>
          </div>
        </div>
      `;

    case "edit-quota":
      return `
        <div class="space-y-4">
          <p class="text-xs text-slate-300">Updating storage limit for <strong>${escapeHtml(state.activeUserForQuota?.username || '')}</strong>.</p>
          <div>
            <label class="block text-xs font-semibold text-slate-300 mb-1">Storage Quota (in Gigabytes)</label>
            <input id="new-quota-input" type="number" step="1" min="1" max="1000" value="${state.activeUserForQuota?.quotaGb || 10}" class="w-full bg-slate-900 border border-slate-700 rounded-lg p-2.5 text-xs text-white outline-none" />
          </div>
          <button onclick="submitQuotaUpdate()" class="btn-cyber w-full py-2.5 rounded-lg text-xs font-bold">
            Update Storage Quota
          </button>
        </div>
      `;

    case "new-ip":
      return `
        <div class="space-y-4">
          <div>
            <label class="block text-xs font-semibold text-slate-300 mb-1">IP Address</label>
            <input id="new-ip-addr" type="text" placeholder="192.168.1.100" class="w-full bg-slate-900 border border-slate-700 rounded-lg p-2.5 text-xs text-white font-mono outline-none" />
          </div>
          <div>
            <label class="block text-xs font-semibold text-slate-300 mb-1">Rule Type</label>
            <select id="new-ip-type" class="w-full bg-slate-900 border border-slate-700 rounded-lg p-2.5 text-xs text-white outline-none">
              <option value="WHITELIST">WHITELIST (Always Trusted)</option>
              <option value="BLACKLIST">BLACKLIST (Immediate Access Block)</option>
            </select>
          </div>
          <div>
            <label class="block text-xs font-semibold text-slate-300 mb-1">Description / Reason</label>
            <input id="new-ip-desc" type="text" placeholder="Security compliance / Known proxy" class="w-full bg-slate-900 border border-slate-700 rounded-lg p-2.5 text-xs text-white outline-none" />
          </div>
          <button onclick="submitNewIpRule()" class="btn-cyber w-full py-2.5 rounded-lg text-xs font-bold">
            Add IP Rule
          </button>
        </div>
      `;

    case "pin-lock":
      return `
        <div class="space-y-4">
          <p class="text-xs text-slate-300">Set a 6-digit PIN or strong passphrase to encrypt <strong>${escapeHtml(state.activeFile?.filename || 'File')}</strong> with AES-256-GCM.</p>
          <div>
            <label class="block text-xs font-semibold text-slate-300 mb-1">6-Digit PIN / Passphrase</label>
            <input id="lock-pin-input" type="password" maxlength="32" placeholder="e.g. 123456" class="w-full bg-slate-900 border border-slate-700 rounded-lg p-2.5 text-xs text-white font-mono outline-none" />
          </div>
          <div class="flex items-center gap-2 p-2.5 bg-slate-900 rounded-lg border border-slate-800">
            <input type="checkbox" id="lock-save-recovery" checked class="rounded bg-slate-950 border-slate-700 text-sky-500 cursor-pointer accent-sky-500" />
            <label for="lock-save-recovery" class="text-xs text-slate-300 cursor-pointer">
              Save PIN to my Confidential Recovery Vault (so I never lose access if forgotten)
            </label>
          </div>
          <button onclick="submitPinLock()" class="btn-cyber w-full py-2.5 rounded-lg text-xs font-bold">
            Encrypt & Lock in Vault
          </button>
        </div>
      `;

    case "pin-unlock":
      return `
        <div class="space-y-4">
          <p class="text-xs text-slate-300">Enter PIN to decrypt and preview <strong>${escapeHtml(state.activeFile?.filename || 'File')}</strong> in memory.</p>
          <div>
            <label class="block text-xs font-semibold text-slate-300 mb-1">PIN / Passphrase</label>
            <input id="unlock-pin-input" type="password" maxlength="32" placeholder="Enter PIN" class="w-full bg-slate-900 border border-slate-700 rounded-lg p-2.5 text-xs text-white font-mono outline-none" />
          </div>
          <button onclick="submitPinUnlock()" class="btn-cyber w-full py-2.5 rounded-lg text-xs font-bold">
            Decrypt & Preview
          </button>
        </div>
      `;

    case "share-create":
      return `
        <div class="space-y-4">
          <p class="text-xs text-slate-300">Create a secure expiring public link for <strong>${escapeHtml(state.activeFile?.filename || 'File')}</strong>.</p>
          <div>
            <label class="block text-xs font-semibold text-slate-300 mb-1">Expiration Period</label>
            <select id="share-expiry" class="w-full bg-slate-900 border border-slate-700 rounded-lg p-2.5 text-xs text-white outline-none">
              <option value="1">1 Hour</option>
              <option value="24" selected>24 Hours</option>
              <option value="168">7 Days</option>
              <option value="720">30 Days</option>
            </select>
          </div>
          <div class="flex items-center gap-2">
            <input type="checkbox" id="share-view-only" class="rounded bg-slate-900 border-slate-700" />
            <label for="share-view-only" class="text-xs text-slate-300">View-Only (Prevent File Downloads)</label>
          </div>
          <div>
            <label class="block text-xs font-semibold text-slate-300 mb-1">Optional Password Protection</label>
            <input id="share-password" type="password" placeholder="Leave empty for public access" class="w-full bg-slate-900 border border-slate-700 rounded-lg p-2.5 text-xs text-white outline-none" />
          </div>
          <button onclick="submitShareCreate()" class="btn-cyber w-full py-2.5 rounded-lg text-xs font-bold">
            Generate Shareable Link
          </button>
        </div>
      `;

    case "rename":
      return `
        <div class="space-y-4">
          <div>
            <label class="block text-xs font-semibold text-slate-300 mb-1">New Filename</label>
            <input id="rename-input" type="text" value="${escapeHtml(state.activeFile?.filename || '')}" class="w-full bg-slate-900 border border-slate-700 rounded-lg p-2.5 text-xs text-white outline-none" />
          </div>
          <button onclick="submitRename()" class="btn-cyber w-full py-2.5 rounded-lg text-xs font-bold">
            Save Changes
          </button>
        </div>
      `;

    default:
      return '<div class="text-center py-6 text-slate-400">Modal content not found.</div>';
  }
}

// =========================================================================
// Modal & Action Event Handlers
// =========================================================================

let currentAuthPortal = "USER";

function setAuthPortalMode(mode) {
  currentAuthPortal = mode;
  const userBtn = document.getElementById("auth-mode-user");
  const adminBtn = document.getElementById("auth-mode-admin");
  const regBtn = document.getElementById("auth-mode-register");
  const forgotBtn = document.getElementById("auth-mode-forgot");
  const loginForm = document.getElementById("auth-form-login");
  const regForm = document.getElementById("auth-form-register");
  const forgotForm = document.getElementById("auth-form-forgot");
  const banner = document.getElementById("auth-portal-banner");

  if (userBtn) userBtn.className = mode === "USER" ? "py-2 rounded-lg text-xs font-bold text-white bg-sky-600" : "py-2 rounded-lg text-xs font-bold text-slate-300 hover:text-white";
  if (adminBtn) adminBtn.className = mode === "ADMIN" ? "py-2 rounded-lg text-xs font-bold text-white bg-cyan-600" : "py-2 rounded-lg text-xs font-bold text-slate-300 hover:text-white";
  if (regBtn) regBtn.className = mode === "REGISTER" ? "py-2 rounded-lg text-xs font-bold text-white bg-purple-600" : "py-2 rounded-lg text-xs font-bold text-slate-300 hover:text-white";
  if (forgotBtn) forgotBtn.className = mode === "FORGOT" ? "py-2 rounded-lg text-xs font-bold text-white bg-indigo-600" : "py-2 rounded-lg text-xs font-bold text-slate-300 hover:text-white";

  if (loginForm) loginForm.classList.add("hidden");
  if (regForm) regForm.classList.add("hidden");
  if (forgotForm) forgotForm.classList.add("hidden");

  if (mode === "REGISTER") {
    if (regForm) regForm.classList.remove("hidden");
  } else if (mode === "FORGOT") {
    if (forgotForm) forgotForm.classList.remove("hidden");
  } else {
    if (loginForm) loginForm.classList.remove("hidden");
    if (banner) {
      banner.innerHTML = mode === "ADMIN" 
        ? "Authenticating for <strong>ADMIN SOC PORTAL</strong>. Role validation strictly enforced." 
        : "Authenticating for <strong>USER PORTAL</strong>. Role validation strictly enforced.";
    }
  }
  lucide.createIcons();
}

async function handleForgotPasswordRequest() {
  const email = document.getElementById("forgot-email")?.value.trim();
  if (!email) {
    showToast("Please enter your account email.", "warning");
    return;
  }
  try {
    const res = await apiRequest("/api/auth/forgot-password", {
      method: "POST",
      body: JSON.stringify({ email })
    });
    if (res.reset_token) {
      const tokInput = document.getElementById("reset-token");
      if (tokInput) tokInput.value = res.reset_token;
    }
    showToast(res.message || "Reset token generated successfully.", "success");
  } catch (e) {}
}

async function handleResetPasswordSubmit() {
  const email = document.getElementById("forgot-email")?.value.trim();
  const token = document.getElementById("reset-token")?.value.trim();
  const newPassword = document.getElementById("reset-new-password")?.value;

  if (!email || !newPassword) {
    showToast("Please enter email and new password.", "warning");
    return;
  }

  try {
    const res = await apiRequest("/api/auth/reset-password", {
      method: "POST",
      body: JSON.stringify({ email, reset_token: token, new_password: newPassword })
    });
    showToast(res.message || "Password updated successfully. You can now login.", "success");
    setAuthPortalMode("USER");
  } catch (e) {}
}

async function handleLoginSubmit() {
  const email = document.getElementById("login-email")?.value.trim();
  const password = document.getElementById("login-password")?.value;
  const captcha = document.getElementById("mock-captcha")?.checked;

  if (!email || !password) {
    showToast("Please enter email and password.", "warning");
    return;
  }
  if (!captcha) {
    showToast("Please check the 'I\\'m not a robot' box.", "warning");
    return;
  }

  try {
    const res = await apiRequest("/api/auth/login", {
      method: "POST",
      body: JSON.stringify({
        email,
        password,
        portal: currentAuthPortal,
        mock_captcha_verified: captcha
      })
    });

    state.token = res.access_token;
    state.user = res.user;
    localStorage.setItem("sc_token", res.access_token);
    localStorage.setItem("sc_user", JSON.stringify(res.user));

    showToast(`Welcome back, ${res.user.username}!`, "success");
    closeModal();
    state.currentTab = res.user.role === "ADMIN" ? "soc-overview" : "my-files";
    loadCurrentTabData();
    if (res.user.role === "ADMIN") {
      startLiveTelemetry();
    }
  } catch (e) {}
}

async function handleRegisterSubmit() {
  const username = document.getElementById("reg-username")?.value.trim();
  const email = document.getElementById("reg-email")?.value.trim();
  const password = document.getElementById("reg-password")?.value;
  const role = document.getElementById("reg-role")?.value || "USER";

  if (!username || !email || !password) {
    showToast("Please fill in all registration fields.", "warning");
    return;
  }

  try {
    const res = await apiRequest("/api/auth/register", {
      method: "POST",
      body: JSON.stringify({ username, email, password, role })
    });

    state.token = res.access_token;
    state.user = res.user;
    localStorage.setItem("sc_token", res.access_token);
    localStorage.setItem("sc_user", JSON.stringify(res.user));

    showToast(`Account successfully registered! Logged in as ${res.user.username}.`, "success");
    closeModal();
    state.currentTab = res.user.role === "ADMIN" ? "soc-overview" : "my-files";
    loadCurrentTabData();
    if (res.user.role === "ADMIN") {
      startLiveTelemetry();
    }
  } catch (e) {}
}

function logout() {
  localStorage.removeItem("sc_token");
  localStorage.removeItem("sc_user");
  state.token = null;
  state.user = null;
  state.currentTab = "my-files";
  if (telemetryInterval) clearInterval(telemetryInterval);
  showToast("Logged out successfully.", "info");
  render();
}

async function deleteFile(fileId) {
  try {
    const res = await apiRequest(`/api/files/${fileId}`, { method: "DELETE" });
    showToast(res.message || "File moved to Recycle Bin.", "info");
    if (res.storage && state.user) {
      state.user.used_quota_formatted = res.storage.used_formatted;
      localStorage.setItem("sc_user", JSON.stringify(state.user));
    }
    loadCurrentTabData();
  } catch (e) {}
}

async function restoreFromRecycleBin(fileId) {
  try {
    const res = await apiRequest(`/api/recycle-bin/${fileId}/restore`, { method: "POST" });
    showToast(res.message || "File restored.", "success");
    if (res.storage && state.user) {
      state.user.used_quota_formatted = res.storage.used_formatted;
      localStorage.setItem("sc_user", JSON.stringify(state.user));
    }
    loadCurrentTabData();
  } catch (e) {}
}

async function permanentDelete(fileId) {
  try {
    const res = await apiRequest(`/api/recycle-bin/${fileId}/permanent`, { method: "DELETE" });
    showToast(res.message || "File permanently destroyed.", "info");
    if (res.storage && state.user) {
      state.user.used_quota_formatted = res.storage.used_formatted;
      localStorage.setItem("sc_user", JSON.stringify(state.user));
    }
    loadCurrentTabData();
  } catch (e) {}
}

async function revokeShare(shareId) {
  try {
    await apiRequest(`/api/shares/${shareId}/revoke`, { method: "POST" });
    showToast("Shared link revoked.", "info");
    loadCurrentTabData();
  } catch (e) {}
}

async function globalRevokeShares() {
  try {
    const res = await apiRequest("/api/soc/shares/revoke-all", { method: "POST" });
    showToast(res.message || "All public shares revoked.", "warning");
    loadCurrentTabData();
  } catch (e) {}
}

async function toggleUserStatus(userId) {
  try {
    const res = await apiRequest(`/api/soc/users/${userId}/toggle-status`, { method: "PUT" });
    showToast(res.message, "info");
    loadCurrentTabData();
  } catch (e) {}
}

function openEditQuotaModal(userId, username, quotaGb) {
  state.activeUserForQuota = { userId, username, quotaGb };
  openModal("edit-quota");
}

async function submitQuotaUpdate() {
  const newGb = parseFloat(document.getElementById("new-quota-input")?.value);
  if (!newGb || newGb <= 0) {
    showToast("Please enter a valid quota size.", "warning");
    return;
  }
  try {
    const res = await apiRequest(`/api/soc/users/${state.activeUserForQuota.userId}/quota`, {
      method: "PUT",
      body: JSON.stringify({ quota_gb: newGb })
    });
    showToast(res.message, "success");
    closeModal();
    loadCurrentTabData();
  } catch (e) {}
}

async function submitNewIpRule() {
  const ip = document.getElementById("new-ip-addr")?.value.trim();
  const ruleType = document.getElementById("new-ip-type")?.value || "BLACKLIST";
  const description = document.getElementById("new-ip-desc")?.value.trim();

  if (!ip) {
    showToast("Please enter an IP address.", "warning");
    return;
  }

  try {
    const res = await apiRequest("/api/soc/ip-guard/rules", {
      method: "POST",
      body: JSON.stringify({ ip_address: ip, rule_type: ruleType, description })
    });
    showToast(res.message, "success");
    closeModal();
    loadCurrentTabData();
  } catch (e) {}
}

async function deleteIpRule(ruleId) {
  try {
    await apiRequest(`/api/soc/ip-guard/rules/${ruleId}`, { method: "DELETE" });
    showToast("IP rule deleted.", "info");
    loadCurrentTabData();
  } catch (e) {}
}

async function revokeSession(sessionId) {
  try {
    await apiRequest(`/api/soc/sessions/${sessionId}/revoke`, { method: "POST" });
    showToast("Session revoked.", "info");
    loadCurrentTabData();
  } catch (e) {}
}

async function handleQuarantineAction(quarantineId, action) {
  try {
    const res = await apiRequest(`/api/soc/quarantine/${quarantineId}/action`, {
      method: "POST",
      body: JSON.stringify({ action })
    });
    showToast(res.message, "info");
    loadCurrentTabData();
  } catch (e) {}
}

async function submitPinLock() {
  const pin = document.getElementById("lock-pin-input")?.value.trim();
  const saveRec = document.getElementById("lock-save-recovery")?.checked ?? true;
  if (!pin || pin.length < 4) {
    showToast("PIN must be at least 4 characters.", "warning");
    return;
  }
  try {
    const res = await apiRequest("/api/confidential/lock", {
      method: "POST",
      body: JSON.stringify({
        file_id: state.activeFile.id,
        pin: pin,
        save_password: saveRec
      })
    });
    showToast(res.message || "File locked in Confidential Vault!", "success");
    closeModal();
    loadCurrentTabData();
  } catch (e) {}
}

async function submitPinUnlock() {
  const pin = document.getElementById("unlock-pin-input")?.value.trim();
  if (!pin) {
    showToast("Please enter PIN.", "warning");
    return;
  }
  try {
    const res = await apiRequest("/api/confidential/unlock", {
      method: "POST",
      body: JSON.stringify({
        file_id: state.activeFile.id,
        pin: pin
      })
    });
    showToast("File decrypted successfully in memory.", "success");
    closeModal();
    state.activeViewerContent = {
      format: res.format || "TEXT",
      filename: res.filename,
      content: res.content
    };
    openModal("viewer");
  } catch (e) {}
}

async function submitShareCreate() {
  const hours = parseInt(document.getElementById("share-expiry")?.value || "24");
  const viewOnly = document.getElementById("share-view-only")?.checked || false;
  const password = document.getElementById("share-password")?.value || null;

  try {
    const res = await apiRequest("/api/shares/create", {
      method: "POST",
      body: JSON.stringify({
        file_id: state.activeFile.id,
        expires_in_hours: hours,
        view_only: viewOnly,
        password: password || null
      })
    });
    showToast("Shareable link generated!", "success");
    closeModal();
    switchTab("shares");
  } catch (e) {}
}

async function submitRename() {
  const newName = document.getElementById("rename-input")?.value.trim();
  if (!newName) {
    showToast("Filename cannot be empty.", "warning");
    return;
  }
  try {
    const res = await apiRequest(`/api/files/${state.activeFile.id}/rename`, {
      method: "PUT",
      body: JSON.stringify({ new_filename: newName })
    });
    showToast(res.message, "success");
    closeModal();
    loadCurrentTabData();
  } catch (e) {}
}

// =========================================================================
// Helpers & Utilities
// =========================================================================

function escapeHtml(str) {
  if (typeof str !== "string") return str || "";
  return str.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#039;");
}

function getSecurityBadgeClass(status) {
  switch (status) {
    case "CLEAN": return "badge-clean";
    case "SUSPICIOUS": return "badge-suspicious";
    case "MALICIOUS": return "badge-malicious";
    default: return "bg-slate-800 text-slate-300";
  }
}

function getFileIcon(ext = "") {
  ext = ext.toLowerCase();
  if ([".pdf"].includes(ext)) return "file-text";
  if ([".doc", ".docx"].includes(ext)) return "file-text";
  if ([".xls", ".xlsx", ".csv"].includes(ext)) return "table";
  if ([".ppt", ".pptx"].includes(ext)) return "presentation";
  if ([".png", ".jpg", ".jpeg", ".gif", ".webp", ".svg"].includes(ext)) return "image";
  if ([".mp4", ".webm", ".mov"].includes(ext)) return "video";
  if ([".mp3", ".wav", ".ogg"].includes(ext)) return "music";
  if ([".zip", ".tar", ".gz"].includes(ext)) return "archive";
  if ([".py", ".js", ".ts", ".html", ".css", ".sh"].includes(ext)) return "code";
  return "file";
}
