import React, { createContext, useContext, useState, useEffect } from 'react';
import { authApi } from '../api/authApi';

const AuthContext = createContext(null);

export function AuthProvider({ children }) {
  // Session-bound authentication: closing the browser window/tab immediately clears the session
  const [token, setToken] = useState(() => {
    // Clear legacy localStorage to enforce login screen by default on browser open
    localStorage.removeItem('sc_token');
    localStorage.removeItem('sc_user');
    return sessionStorage.getItem('sc_token') || null;
  });

  const [user, setUser] = useState(() => {
    try {
      const stored = sessionStorage.getItem('sc_user');
      return stored ? JSON.parse(stored) : null;
    } catch {
      return null;
    }
  });

  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const handleUnauthorized = () => {
      logout();
    };
    window.addEventListener('auth:unauthorized', handleUnauthorized);

    if (token) {
      refreshUser().finally(() => setLoading(false));
    } else {
      setLoading(false);
    }

    return () => {
      window.removeEventListener('auth:unauthorized', handleUnauthorized);
    };
  }, [token]);

  const refreshUser = async () => {
    try {
      const profile = await authApi.getMe();
      setUser(profile);
      sessionStorage.setItem('sc_user', JSON.stringify(profile));
      return profile;
    } catch (err) {
      console.warn("Failed to refresh user profile:", err.message);
      logout();
      return null;
    }
  };

  const login = async ({ email, password, portal = 'USER', mock_captcha_verified = true, totp_code = null, admin_security_code = null }) => {
    const res = await authApi.login({
      email,
      password,
      portal,
      mock_captcha_verified,
      totp_code,
      admin_security_code
    });

    if (res.requires_2fa) {
      return res;
    }

    setToken(res.access_token);
    setUser(res.user);
    sessionStorage.setItem('sc_token', res.access_token);
    sessionStorage.setItem('sc_user', JSON.stringify(res.user));
    return res;
  };

  const register = async ({ username, email, password, role = 'USER', admin_security_code = null }) => {
    const res = await authApi.register({ username, email, password, role, admin_security_code });
    setToken(res.access_token);
    setUser(res.user);
    sessionStorage.setItem('sc_token', res.access_token);
    sessionStorage.setItem('sc_user', JSON.stringify(res.user));
    return res;
  };

  const logout = () => {
    setToken(null);
    setUser(null);
    sessionStorage.removeItem('sc_token');
    sessionStorage.removeItem('sc_user');
    localStorage.removeItem('sc_token');
    localStorage.removeItem('sc_user');
  };

  const updateUserQuotaLocally = (storageMetrics) => {
    if (!user || !storageMetrics) return;
    const updated = {
      ...user,
      used_quota_bytes: storageMetrics.used_bytes,
      used_quota_formatted: storageMetrics.used_formatted,
      quota_formatted: storageMetrics.quota_formatted
    };
    setUser(updated);
    sessionStorage.setItem('sc_user', JSON.stringify(updated));
  };

  const value = {
    token,
    user,
    loading,
    isAuthenticated: !!token && !!user,
    isAdmin: !!user && user.role === 'ADMIN',
    login,
    register,
    logout,
    refreshUser,
    updateUserQuotaLocally
  };

  return (
    <AuthContext.Provider value={value}>
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth() {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
}
