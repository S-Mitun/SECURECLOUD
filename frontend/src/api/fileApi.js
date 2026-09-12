import { apiClient, API_BASE_URL } from './apiClient';

export const fileApi = {
  listFiles: async () => {
    return await apiClient('/api/files/list');
  },

  uploadFile: async (fileOrFormData) => {
    let body = fileOrFormData;
    if (fileOrFormData instanceof File || fileOrFormData instanceof Blob) {
      body = new FormData();
      body.append('file', fileOrFormData);
    }
    return await apiClient('/api/files/upload', {
      method: 'POST',
      body
    });
  },

  viewFile: async (fileId) => {
    return await apiClient(`/api/files/${fileId}/view`);
  },

  getDownloadUrl: (fileId) => {
    return `${API_BASE_URL}/api/files/${fileId}/download`;
  },

  getStreamUrl: (fileId) => {
    return `${API_BASE_URL}/api/files/${fileId}/stream`;
  },

  renameFile: async (fileId, new_filename) => {
    return await apiClient(`/api/files/${fileId}/rename`, {
      method: 'PUT',
      body: JSON.stringify({ new_filename })
    });
  },

  deleteFile: async (fileId) => {
    return await apiClient(`/api/files/${fileId}`, {
      method: 'DELETE'
    });
  },

  // Recycle Bin
  listRecycleBin: async () => {
    return await apiClient('/api/recycle-bin/list');
  },

  restoreFile: async (fileId) => {
    return await apiClient(`/api/recycle-bin/${fileId}/restore`, {
      method: 'POST'
    });
  },

  permanentDelete: async (fileId) => {
    return await apiClient(`/api/recycle-bin/${fileId}/permanent`, {
      method: 'DELETE'
    });
  },

  // Confidential Vault
  listConfidential: async () => {
    return await apiClient('/api/confidential/list');
  },

  lockConfidential: async ({ file_id, pin, save_password = true }) => {
    return await apiClient('/api/confidential/lock', {
      method: 'POST',
      body: JSON.stringify({ file_id, pin, save_password })
    });
  },

  unlockConfidential: async ({ file_id, pin }) => {
    return await apiClient('/api/confidential/unlock', {
      method: 'POST',
      body: JSON.stringify({ file_id, pin })
    });
  },

  listSavedPasswords: async () => {
    return await apiClient('/api/confidential/saved-passwords');
  },

  // Shared Links
  listShares: async () => {
    return await apiClient('/api/shares/list');
  },

  createShare: async ({ file_id, expires_in_hours = 24, view_only = false, password = null }) => {
    return await apiClient('/api/shares/create', {
      method: 'POST',
      body: JSON.stringify({ file_id, expires_in_hours, view_only, password })
    });
  },

  revokeShare: async (shareId) => {
    return await apiClient(`/api/shares/${shareId}/revoke`, {
      method: 'POST'
    });
  },

  getPublicShareInfo: async (shareId) => {
    return await apiClient(`/api/shares/public/${shareId}`);
  },

  // File Versioning
  listVersions: async (fileId) => {
    return await apiClient(`/api/files/${fileId}/versions`);
  },

  uploadVersion: async (fileId, fileOrFormData) => {
    let body = fileOrFormData;
    if (fileOrFormData instanceof File || fileOrFormData instanceof Blob) {
      body = new FormData();
      body.append('file', fileOrFormData);
    }
    return await apiClient(`/api/files/${fileId}/versions`, {
      method: 'POST',
      body
    });
  },

  restoreVersion: async (fileId, versionId) => {
    return await apiClient(`/api/files/${fileId}/versions/${versionId}/restore`, {
      method: 'POST'
    });
  }
};
