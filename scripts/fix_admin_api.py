with open("frontend/src/api/adminApi.js", "r", encoding="utf-8") as f:
    text = f.read()

text = text.replace(
    """  revokeVerifiedArtifact: async (artifactId) => {
    return await apiClient(`/api/soc/verified-clean/${artifactId}/revoke`, {
      method: 'POST'
    });
  }""",
    """  revokeVerifiedArtifact: async (artifactId) => {
    return await apiClient(`/api/soc/verified-clean/${artifactId}/revoke`, {
      method: 'POST'
    });
  },"""
)

with open("frontend/src/api/adminApi.js", "w", encoding="utf-8") as f:
    f.write(text)

print("[OK] Fixed comma in adminApi.js!")
