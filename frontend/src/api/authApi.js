import { apiClient } from './apiClient';

export const authApi = {
  login: async ({ email, password, portal = 'USER', totp_code = null }) => {
    return await apiClient('/api/auth/login', {
      method: 'POST',
      body: JSON.stringify({
        email,
        password,
        portal_type: portal,
        portal,
        totp_code
      })
    });
  },

  register: async ({ username, email, password, role = 'USER' }) => {
    return await apiClient('/api/auth/register', {
      method: 'POST',
      body: JSON.stringify({
        username,
        email,
        password,
        role
      })
    });
  },

  getMe: async () => {
    return await apiClient('/api/auth/me');
  },

  forgotPassword: async (email) => {
    return await apiClient('/api/auth/forgot-password', {
      method: 'POST',
      body: JSON.stringify({ email })
    });
  },

  resetPassword: async ({ email, reset_token, new_password }) => {
    return await apiClient('/api/auth/reset-password', {
      method: 'POST',
      body: JSON.stringify({
        email,
        reset_token,
        new_password
      })
    });
  },

  getSessions: async () => {
    return await apiClient('/api/auth/sessions');
  },

  setup2FA: async () => {
    return await apiClient('/api/auth/2fa/setup', { method: 'POST' });
  },

  verify2FA: async (totp_code) => {
    return await apiClient('/api/auth/2fa/verify', {
      method: 'POST',
      body: JSON.stringify({ totp_code })
    });
  },

  triggerEmergencyLockdown: async ({ password, acknowledgement = true, reason = '' }) => {
    return await apiClient('/api/auth/emergency-lockdown', {
      method: 'POST',
      body: JSON.stringify({ password, acknowledgement, reason })
    });
  }
};
