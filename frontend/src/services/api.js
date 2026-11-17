/**
 * src/services/api.js
 * 
 * Centralized API client connecting the React dashboard to the FastAPI gateway.
 * Security:
 * - In-Memory Token Storage: Tokens are held purely in React transient memory,
 *   never persisted in localStorage or sessionStorage to protect against XSS exfiltration.
 * - Auto-Interception on 401 Unauthorized to reset session state.
 */

const BASE_URL = import.meta.env.VITE_API_BASE_URL || "http://localhost:8000";

let inMemoryToken = null;
let unauthorizedHandler = null;

export const setAuthToken = (token) => {
  inMemoryToken = token;
};

export const getAuthToken = () => inMemoryToken;

export const setOnUnauthorized = (callback) => {
  unauthorizedHandler = callback;
};

async function request(endpoint, options = {}) {
  const url = `${BASE_URL}${endpoint}`;
  const defaultHeaders = {
    "Content-Type": "application/json",
    "Accept": "application/json",
  };

  if (inMemoryToken) {
    defaultHeaders["Authorization"] = `Bearer ${inMemoryToken}`;
  }

  const config = {
    ...options,
    headers: {
      ...defaultHeaders,
      ...options.headers,
    },
  };

  try {
    const response = await fetch(url, config);

    // 204 No Content
    if (response.status === 204) {
      return null;
    }

    // 401 Unauthorized: Session expired or invalid token
    if (response.status === 401 && endpoint !== "/auth/login") {
      inMemoryToken = null;
      if (unauthorizedHandler) {
        unauthorizedHandler();
      }
    }

    const data = await response.json().catch(() => ({}));

    if (!response.ok) {
      const errorMsg = data.detail || `Request failed with status ${response.status}`;
      const error = new Error(errorMsg);
      error.status = response.status;
      error.data = data;
      throw error;
    }

    return data;
  } catch (error) {
    if (endpoint !== "/health") {
      console.error(`API Error on [${options.method || "GET"} ${endpoint}]:`, error);
    }
    throw error;
  }
}

export const api = {
  // System
  checkHealth: () => request("/health"),

  // Authentication & Identity
  login: (username, password) =>
    request("/auth/login", {
      method: "POST",
      body: JSON.stringify({ username, password }),
    }),
  logout: async () => {
    try {
      await request("/auth/logout", { method: "POST" });
    } finally {
      inMemoryToken = null;
    }
  },
  getMe: () => request("/auth/me"),

  // API Registry
  listApis: () => request("/apis"),
  getApi: (id) => request(`/apis/${id}`),
  createApi: (payload) => request("/apis", { method: "POST", body: JSON.stringify(payload) }),
  deleteApi: (id) => request(`/apis/${id}`, { method: "DELETE" }),

  // Tasks & Orchestration
  processTask: (task) => request("/tasks", { method: "POST", body: JSON.stringify({ task }) }),

  // Approvals
  listApprovals: () => request("/approvals"),
  approveRequest: (id) => request(`/approvals/${id}/approve`, { method: "POST" }),
  rejectRequest: (id) => request(`/approvals/${id}/reject`, { method: "POST" }),

  // Audit Logs & Replay
  listLogs: (params = {}) => {
    const query = new URLSearchParams();
    if (params.api_id) query.append("api_id", params.api_id);
    if (params.status) query.append("status", params.status);
    if (params.skip !== undefined) query.append("skip", params.skip);
    if (params.limit !== undefined) query.append("limit", params.limit);
    const qs = query.toString() ? `?${query.toString()}` : "";
    return request(`/logs${qs}`);
  },
  getLog: (id) => request(`/logs/${id}`),
  replayLog: (id) => request(`/logs/${id}/replay`, { method: "POST" }),
};
