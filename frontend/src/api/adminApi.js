import { apiClient } from './apiClient';

export const adminApi = {
  getDashboard: async () => {
    return await apiClient('/api/soc/dashboard');
  },

  getTelemetry: async () => {
    return await apiClient('/api/soc/telemetry');
  },

  simulateSentinelPhase: async (phase) => {
    return await apiClient('/api/soc/telemetry/simulate-phase', {
      method: 'POST',
      body: JSON.stringify({ phase })
    });
  },

  // Users & User-wise Grouped Files
  listUsers: async () => {
    return await apiClient('/api/soc/users');
  },

  getUserGroupedFiles: async () => {
    return await apiClient('/api/soc/users/grouped-files');
  },

  getUserFiles: async (userId) => {
    return await apiClient(`/api/soc/users/${userId}/files`);
  },

  updateUserQuota: async (userId, quota_gb) => {
    return await apiClient(`/api/soc/users/${userId}/quota`, {
      method: 'PUT',
      body: JSON.stringify({ quota_gb: parseFloat(quota_gb) })
    });
  },

  toggleUserStatus: async (userId) => {
    return await apiClient(`/api/soc/users/${userId}/toggle-status`, {
      method: 'PUT'
    });
  },

  // Platform Files
  listAllFiles: async () => {
    return await apiClient('/api/files/all');
  },

  // Multi-Stage File Scanning with Dual-Admin Authorization
  scanFile: async (fileId, adminAuthCode = '') => {
    const headers = adminAuthCode ? { 'X-Admin-Auth-Code': adminAuthCode } : {};
    return await apiClient(`/api/soc/files/${fileId}/scan`, {
      method: 'POST',
      headers
    });
  },

  rescanFile: async (fileId, adminAuthCode = '') => {
    const headers = adminAuthCode ? { 'X-Admin-Auth-Code': adminAuthCode } : {};
    return await apiClient(`/api/soc/files/${fileId}/rescan`, {
      method: 'POST',
      headers
    });
  },

  retriggerScan: async (fileId, adminAuthCode = '') => {
    const headers = adminAuthCode ? { 'X-Admin-Auth-Code': adminAuthCode } : {};
    return await apiClient(`/api/soc/files/${fileId}/rescan`, {
      method: 'POST',
      headers
    });
  },

  // Threat Intelligence Correlation Engine
  getThreatCorrelation: async () => {
    return await apiClient('/api/soc/threat-intelligence/correlation');
  },

  getThreatOverview: async () => {
    return await apiClient('/api/soc/threat-intelligence/overview');
  },

  getThreatIndicators: async () => {
    return await apiClient('/api/soc/threat-intelligence/indicators');
  },

  addThreatIndicator: async (payload) => {
    return await apiClient('/api/soc/threat-intelligence/indicators', {
      method: 'POST',
      body: JSON.stringify(payload)
    });
  },

  deleteThreatIndicator: async (id) => {
    return await apiClient(`/api/soc/threat-intelligence/indicators/${id}`, {
      method: 'DELETE'
    });
  },

  mitigateThreatCluster: async (clusterId, action, options = ['OPTION_1', 'OPTION_2', 'OPTION_3', 'OPTION_4']) => {
    return await apiClient('/api/soc/threat-intelligence/mitigate-cluster', {
      method: 'POST',
      body: JSON.stringify({ cluster_id: clusterId, action, options })
    });
  },

  // User Risk Profiling Matrix
  getUserRiskProfiling: async () => {
    return await apiClient('/api/soc/analytics/risk-profiling');
  },

  getRiskUsers: async () => {
    return await apiClient('/api/soc/risk/users');
  },

  getUserRiskDetail: async (userId) => {
    return await apiClient(`/api/soc/risk/users/${userId}`);
  },

  getUserRiskTimeline: async (userId) => {
    return await apiClient(`/api/soc/risk/users/${userId}/timeline`);
  },

  recalculateUserRisk: async (userId) => {
    return await apiClient(`/api/soc/risk/users/${userId}/recalculate`, {
      method: 'POST'
    });
  },

  enforceUser2FA: async (userId) => {
    return await apiClient('/api/soc/analytics/risk-profiling/enforce-2fa', {
      method: 'POST',
      body: JSON.stringify({ user_id: userId })
    });
  },

  lockdownUserProfile: async (userId, reason = 'Critical Behavioral Risk Score') => {
    return await apiClient('/api/soc/analytics/risk-profiling/lockdown-user', {
      method: 'POST',
      body: JSON.stringify({ user_id: userId, reason })
    });
  },

  // Scan History & Explanations
  getScanHistory: async (fileId) => {
    return await apiClient(`/api/soc/files/${fileId}/scan-history`);
  },

  getAllScansHistory: async () => {
    return await apiClient('/api/soc/scans/history');
  },

  getSecurityDetails: async (fileId) => {
    return await apiClient(`/api/soc/files/${fileId}/security-details`);
  },

  overrideFileToClean: async (fileId) => {
    return await apiClient(`/api/soc/files/${fileId}/override-clean`, {
      method: 'POST'
    });
  },

  purgeThreatFile: async (fileId) => {
    return await apiClient(`/api/soc/files/${fileId}/purge-threat`, {
      method: 'POST'
    });
  },

  // Security Incidents
  listSecurityIncidents: async () => {
    return await apiClient('/api/soc/security/incidents');
  },

  resolveSecurityIncident: async (incidentId) => {
    return await apiClient(`/api/soc/security/incidents/${incidentId}/resolve`, {
      method: 'POST'
    });
  },

  // Threats & Quarantine
  listThreats: async () => {
    return await apiClient('/api/soc/threats');
  },

  listQuarantine: async () => {
    return await apiClient('/api/soc/quarantine/list');
  },

  quarantineAction: async (quarantineId, action) => {
    return await apiClient(`/api/soc/quarantine/${quarantineId}/action`, {
      method: 'POST',
      body: JSON.stringify({ action })
    });
  },

  // IP Access Guard
  listIpRules: async () => {
    return await apiClient('/api/soc/ip-guard/list');
  },

  addIpRule: async ({ ip_address, rule_type = 'BLACKLIST', description = '' }) => {
    return await apiClient('/api/soc/ip-guard/rules', {
      method: 'POST',
      body: JSON.stringify({ ip_address, rule_type, description })
    });
  },

  deleteIpRule: async (ruleId) => {
    return await apiClient(`/api/soc/ip-guard/rules/${ruleId}`, {
      method: 'DELETE'
    });
  },

  // Sessions & Shares
  listSessions: async () => {
    return await apiClient('/api/soc/sessions');
  },

  revokeSession: async (sessionId) => {
    return await apiClient(`/api/soc/sessions/${sessionId}/revoke`, {
      method: 'POST'
    });
  },

  revokeAllShares: async () => {
    return await apiClient('/api/soc/shares/revoke-all', {
      method: 'POST'
    });
  },

  // Audit Logs & Timeline
  listAuditLogs: async (limit = 100, action = '') => {
    const url = action ? `/api/soc/audit-logs?limit=${limit}&action=${encodeURIComponent(action)}` : `/api/soc/audit-logs?limit=${limit}`;
    return await apiClient(url);
  },

  getUserTimeline: async (userId) => {
    return await apiClient(`/api/soc/timeline/${userId}`);
  },

  // Verified Clean Artifact Trust Registry
  listVerifiedArtifacts: async () => {
    return await apiClient('/api/soc/verified-clean');
  },

  revokeVerifiedArtifact: async (artifactId) => {
    return await apiClient(`/api/soc/verified-clean/${artifactId}/revoke`, {
      method: 'POST'
    });
  },

  // Admin File Ingestion for Users
  uploadFileForUser: async (formData) => {
    return await apiClient('/api/soc/files/upload-for-user', {
      method: 'POST',
      body: formData
    });
  },
};
