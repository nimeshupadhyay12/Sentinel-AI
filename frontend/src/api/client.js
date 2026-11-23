import axios from 'axios';

const API_BASE = import.meta.env.VITE_API_BASE || '';

// The short-lived access token lives only in memory (never localStorage), so a
// script injected into the page cannot read a persisted credential. The
// long-lived refresh token is an httpOnly, SameSite=Strict cookie scoped to
// /api/auth that JavaScript cannot read at all. A page reload restores the
// session by calling /api/auth/refresh.
let accessToken = null;
let refreshInFlight = null;
let onSessionExpired = () => {};

export function setAccessToken(token) {
  accessToken = token;
}

export function setSessionExpiredHandler(handler) {
  onSessionExpired = handler;
}

const client = axios.create({ baseURL: API_BASE, withCredentials: true });

client.interceptors.request.use((config) => {
  if (accessToken) {
    config.headers.Authorization = `Bearer ${accessToken}`;
  }
  return config;
});

// Exchange the refresh cookie for a new access token. Concurrent callers share
// one request, because the server rotates the refresh token on every use and
// treats reuse of an old one as theft.
export function refreshSession() {
  if (!refreshInFlight) {
    refreshInFlight = axios
      .post(`${API_BASE}/api/auth/refresh`, null, { withCredentials: true })
      .then((res) => {
        setAccessToken(res.data.access_token);
        return res.data;
      })
      .finally(() => {
        refreshInFlight = null;
      });
  }
  return refreshInFlight;
}

client.interceptors.response.use(
  (response) => response,
  async (error) => {
    const original = error.config;
    const status = error.response?.status;
    const isAuthCall = original?.url?.startsWith('/api/auth/');
    if (status === 401 && original && !original._retried && !isAuthCall) {
      original._retried = true;
      try {
        await refreshSession();
        return client(original);
      } catch {
        setAccessToken(null);
        onSessionExpired();
      }
    }
    return Promise.reject(error);
  }
);

export async function logout() {
  try {
    await client.post('/api/auth/logout');
  } finally {
    setAccessToken(null);
  }
}

export default client;
