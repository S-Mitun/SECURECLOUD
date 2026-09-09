/**
 * SecureCloud - Resilient Centralized API Client
 * Uses session-bound token storage to ensure login page appears on every fresh browser visit.
 */

const isLocalhost = typeof window !== 'undefined' && 
  (window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1');

export const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || (isLocalhost ? 'http://127.0.0.1:8000' : '');

const BASE_URL_CANDIDATES = [
  API_BASE_URL,
  ...(isLocalhost ? ['http://127.0.0.1:8000', 'http://localhost:8000', ''] : ['', 'http://127.0.0.1:8000'])
];

export async function apiClient(endpoint, options = {}) {
  const token = sessionStorage.getItem('sc_token') || localStorage.getItem('sc_token');
  const headers = options.headers ? { ...options.headers } : {};

  if (token) {
    headers['Authorization'] = `Bearer ${token}`;
  }

  // Set Content-Type to application/json only if body is NOT FormData
  if (!(options.body instanceof FormData) && !headers['Content-Type']) {
    headers['Content-Type'] = 'application/json';
  }

  if (endpoint.startsWith('http')) {
    return _fetchSingle(endpoint, options, headers, endpoint);
  }

  let lastError = null;
  const candidates = Array.from(new Set(BASE_URL_CANDIDATES));

  for (const base of candidates) {
    const url = `${base}${endpoint}`;
    try {
      return await _fetchSingle(url, options, headers, endpoint);
    } catch (err) {
      lastError = err;
      if (err.status && err.status >= 400) {
        throw err;
      }
      console.warn(`Connection to ${url} failed, trying alternative host...`);
    }
  }

  throw lastError || new Error('Failed to connect to SecureCloud backend.');
}

async function _fetchSingle(url, options, headers, originalEndpoint = '') {
  const res = await fetch(url, {
    ...options,
    headers
  });

  if (
    res.status === 401 &&
    !originalEndpoint.includes('/auth/login') &&
    !originalEndpoint.includes('/auth/register') &&
    !originalEndpoint.includes('/shares/public') &&
    !originalEndpoint.includes('/auth/forgot-password') &&
    !originalEndpoint.includes('/auth/reset-password') &&
    !originalEndpoint.includes('/confidential/unlock') &&
    !originalEndpoint.includes('/confidential/')
  ) {
    sessionStorage.removeItem('sc_token');
    sessionStorage.removeItem('sc_user');
    localStorage.removeItem('sc_token');
    localStorage.removeItem('sc_user');
    window.dispatchEvent(new CustomEvent('auth:unauthorized'));
    const err = new Error('Your session has expired. Please log in again.');
    err.status = 401;
    throw err;
  }

  const data = await res.json().catch(() => ({}));
  if (!res.ok) {
    const errorMsg = data.detail || data.message || `Request failed with status ${res.status}`;
    const err = new Error(errorMsg);
    err.status = res.status;
    throw err;
  }

  return data;
}
