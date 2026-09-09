with open("frontend/src/api/adminApi.js", "r", encoding="utf-8") as f:
    text = f.read()

new_soc_methods = """
  // Threat Correlation Mitigation Execution
  mitigateThreatCluster: async (clusterId, action) => {
    return await apiClient('/api/soc/threat-intelligence/mitigate-cluster', {
      method: 'POST',
      body: JSON.stringify({ cluster_id: clusterId, action })
    });
  },

  // SOAR Policy History & Manual Trigger
  getPolicyHistory: async (policyId) => {
    return await apiClient(`/api/soc/policies/${policyId}/history`);
  },

  triggerPolicyExecution: async (policyId) => {
    return await apiClient(`/api/soc/policies/${policyId}/trigger`, {
      method: 'POST'
    });
  },

  // User Risk Profiling Direct Actions
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
"""

if "mitigateThreatCluster" not in text:
    text = text.rstrip()
    if text.endswith("};"):
        text = text[:-2] + new_soc_methods + "};"
    elif text.endswith("}"):
        text = text[:-1] + new_soc_methods + "};"
    with open("frontend/src/api/adminApi.js", "w", encoding="utf-8") as f:
        f.write(text)
    print("[OK] Added new methods to frontend/src/api/adminApi.js")
else:
    print("[OK] Methods already present in adminApi.js")
