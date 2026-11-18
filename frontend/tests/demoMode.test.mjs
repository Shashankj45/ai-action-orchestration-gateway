import test from "node:test";
import assert from "node:assert/strict";

import {
  ROLE_DISPLAY,
  DEMO_ROLE_OPTIONS,
  getTabsForRole,
  canAccessTab,
  canMutateAdmin,
} from "../src/utils/rbac.js";
import { api, setAuthToken, getAuthToken, setOnUnauthorized } from "../src/services/api.js";

test("ROLE_DISPLAY maps internal OPERATOR role to User across frontend", () => {
  assert.equal(ROLE_DISPLAY.OPERATOR, "User");
  assert.equal(ROLE_DISPLAY.APPROVER, "Approver");
  assert.equal(ROLE_DISPLAY.ADMIN, "Admin");
});

test("DEMO_ROLE_OPTIONS provides exactly three distinct role entry points", () => {
  assert.equal(DEMO_ROLE_OPTIONS.length, 3);
  assert.deepEqual(
    DEMO_ROLE_OPTIONS.map((o) => o.key),
    ["user", "approver", "admin"]
  );
  assert.deepEqual(
    DEMO_ROLE_OPTIONS.map((o) => o.backendRole),
    ["OPERATOR", "APPROVER", "ADMIN"]
  );
});

test("User (OPERATOR) navigation excludes API Registry, Approver, and Admin tabs", () => {
  const tabs = getTabsForRole("OPERATOR", 2).map((t) => t.id);
  assert.deepEqual(tabs, ["overview", "new_request", "my_requests", "request_history", "profile"]);
  assert.equal(canAccessTab("OPERATOR", "apis"), false);
  assert.equal(canAccessTab("OPERATOR", "approvals"), false);
  assert.equal(canAccessTab("OPERATOR", "users"), false);
  assert.equal(canAccessTab("OPERATOR", "roles"), false);
  assert.equal(canAccessTab("OPERATOR", "security"), false);
});

test("Approver navigation excludes Admin management and User submission tabs", () => {
  const tabs = getTabsForRole("APPROVER", 3).map((t) => t.id);
  assert.deepEqual(tabs, ["overview", "approvals", "approval_history", "request_logs", "profile"]);
  assert.equal(canAccessTab("APPROVER", "apis"), false);
  assert.equal(canAccessTab("APPROVER", "users"), false);
  assert.equal(canAccessTab("APPROVER", "roles"), false);
  assert.equal(canAccessTab("APPROVER", "new_request"), false);
});

test("Admin navigation includes all 8 administration tabs and Demo Admin is read-only", () => {
  const tabs = getTabsForRole("ADMIN", 0).map((t) => t.id);
  assert.deepEqual(tabs, [
    "overview",
    "apis",
    "users",
    "roles",
    "logs",
    "security",
    "monitoring",
    "settings",
  ]);
  assert.equal(canMutateAdmin({ role: "ADMIN", is_demo: false }), true);
  assert.equal(canMutateAdmin({ role: "ADMIN", is_demo: true }), false);
  assert.equal(canMutateAdmin({ role: "APPROVER", is_demo: false }), false);
  assert.equal(canMutateAdmin({ role: "OPERATOR", is_demo: false }), false);
});

test("Switching demo roles via demoSwitchRole replaces session token and preserves isolated demo_session_id", async () => {
  const calls = [];
  const originalFetch = global.fetch;

  global.fetch = async (url, options = {}) => {
    calls.push({ url, method: options.method || "GET", headers: options.headers || {}, body: options.body });

    if (url.endsWith("/auth/demo-login")) {
      const parsed = JSON.parse(options.body);
      const token = `jwt-demo-${parsed.role}`;
      return {
        ok: true,
        status: 200,
        json: async () => ({
          access_token: token,
          token_type: "bearer",
          role: parsed.role === "user" ? "OPERATOR" : parsed.role.toUpperCase(),
          username: `demo_${parsed.role}_sess1234`,
          user_id: `id-${parsed.role}`,
          is_demo: true,
          demo_session_id: "sess-1234-uuid",
          expires_in_minutes: 15,
        }),
      };
    }

    if (url.endsWith("/auth/demo-switch")) {
      const parsed = JSON.parse(options.body);
      const token = `jwt-demo-${parsed.role}-switched`;
      return {
        ok: true,
        status: 200,
        json: async () => ({
          access_token: token,
          token_type: "bearer",
          role: parsed.role === "user" ? "OPERATOR" : parsed.role.toUpperCase(),
          username: `demo_${parsed.role}_sess1234`,
          user_id: `id-${parsed.role}`,
          is_demo: true,
          demo_session_id: "sess-1234-uuid",
          expires_in_minutes: 15,
        }),
      };
    }

    return { ok: true, status: 200, json: async () => ({}) };
  };

  try {
    // 1. Login as Demo Admin
    const adminRes = await api.demoLogin("admin");
    setAuthToken(adminRes.access_token);
    assert.equal(getAuthToken(), "jwt-demo-admin");
    assert.equal(adminRes.is_demo, true);
    assert.equal(adminRes.demo_session_id, "sess-1234-uuid");

    // 2. Switch to Demo User using server-verified /auth/demo-switch
    const userRes = await api.demoSwitchRole("user");
    const switchCall = calls.find((c) => c.url.endsWith("/auth/demo-switch"));
    assert.equal(switchCall.headers.Authorization, "Bearer jwt-demo-admin");
    setAuthToken(userRes.access_token);
    assert.equal(getAuthToken(), "jwt-demo-user-switched");
    assert.equal(userRes.role, "OPERATOR");
    assert.equal(userRes.demo_session_id, "sess-1234-uuid");

    // 3. Subsequent request uses ONLY new Demo User token
    await api.listMyRequests();
    const myReqCall = calls.find((c) => c.url.endsWith("/approvals/my"));
    assert.equal(myReqCall.headers.Authorization, "Bearer jwt-demo-user-switched");
  } finally {
    setAuthToken(null);
    global.fetch = originalFetch;
  }
});

test("401 Unauthorized on protected endpoint clears in-memory token and invokes handler", async () => {
  const originalFetch = global.fetch;
  let unauthorizedCalled = false;
  setOnUnauthorized(() => {
    unauthorizedCalled = true;
  });

  global.fetch = async () => ({
    ok: false,
    status: 401,
    json: async () => ({ detail: "Token has been revoked." }),
  });

  try {
    setAuthToken("stale-demo-token");
    await assert.rejects(() => api.getMe(), /revoked/i);
    assert.equal(getAuthToken(), null);
    assert.equal(unauthorizedCalled, true);
  } finally {
    setOnUnauthorized(null);
    setAuthToken(null);
    global.fetch = originalFetch;
  }
});

test("Auto-entering demo user calls POST /auth/demo-login with user role and receives isolated JWT", async () => {
  const originalFetch = global.fetch;
  let capturedBody = null;

  global.fetch = async (url, options = {}) => {
    if (url.endsWith("/auth/demo-login")) {
      capturedBody = JSON.parse(options.body);
      return {
        ok: true,
        status: 200,
        json: async () => ({
          access_token: "jwt-auto-demo-user",
          token_type: "bearer",
          role: "OPERATOR",
          username: "demo_user_auto1234",
          user_id: "uid-auto-user",
          is_demo: true,
          demo_session_id: "auto-sess-1234",
          expires_in_minutes: 15,
        }),
      };
    }
    return { ok: true, status: 200, json: async () => ({}) };
  };

  try {
    const res = await api.demoLogin("user");
    assert.deepEqual(capturedBody, { role: "user" });
    assert.equal(res.role, "OPERATOR");
    assert.equal(res.is_demo, true);
    assert.equal(res.demo_session_id, "auto-sess-1234");
  } finally {
    setAuthToken(null);
    global.fetch = originalFetch;
  }
});
