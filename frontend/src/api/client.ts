import axios, { AxiosError } from 'axios';
import type { ApiError } from '../types/domain';

// In local development Vite proxies /api -> Spring Boot :8080, so the
// browser needs no CORS configuration. Set VITE_API_BASE_URL when the
// frontend is hosted separately from the API (the backend then needs
// APP_CORS_ALLOWED_ORIGINS to include the frontend origin).
const baseURL = import.meta.env.VITE_API_BASE_URL || '/';

export const api = axios.create({
  baseURL,
  headers: { 'Content-Type': 'application/json' },
  timeout: 20000,
});

// HTTP Basic credentials live only in this module's memory (set by
// AuthContext after a successful login) - never hard-coded or committed.
let authorizationHeader: string | undefined;

export function setAuthCredentials(username: string, password: string): void {
  // btoa only handles Latin-1; encode as UTF-8 first so non-ASCII passwords work.
  const bytes = new TextEncoder().encode(`${username}:${password}`);
  let binary = '';
  bytes.forEach((b) => (binary += String.fromCharCode(b)));
  authorizationHeader = `Basic ${btoa(binary)}`;
}

export function clearAuthCredentials(): void {
  authorizationHeader = undefined;
}

let onUnauthorized: (() => void) | undefined;

export function setUnauthorizedHandler(handler: () => void): void {
  onUnauthorized = handler;
}

api.interceptors.request.use((config) => {
  if (authorizationHeader) {
    config.headers.Authorization = authorizationHeader;
  }
  return config;
});

api.interceptors.response.use(
  (response) => response,
  (error: AxiosError<ApiError>) => {
    const status = error.response?.status;

    // A 401 on an established session (rotated/revoked credentials) drops
    // back to the login screen. The login attempt itself also gets a 401
    // for wrong credentials, which the login form reports on its own.
    if (status === 401 && authorizationHeader) {
      onUnauthorized?.();
    }

    const data = error.response?.data;

    const normalized: ApiError = data && typeof data === 'object' && data.code
      ? { ...data, details: data.details ?? [], status }
      : {
          code: status ? `HTTP_${status}` : 'NETWORK_ERROR',
          message: !status
            ? 'Unable to reach the backend. Check that the API is running.'
            // 502/503/504 come from the dev proxy or a gateway when the API is down or still starting.
            : status === 502 || status === 503 || status === 504
              ? `The backend is not responding (HTTP ${status}). It may still be starting — try again in a moment.`
              : error.message,
          details: [],
          requestId: error.response?.headers?.['x-correlation-id'] || undefined,
          status,
        };

    return Promise.reject(normalized);
  },
);
