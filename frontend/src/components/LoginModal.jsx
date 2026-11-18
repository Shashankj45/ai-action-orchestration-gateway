import React, { useState } from "react";
import { Shield, Lock, User, AlertCircle, ArrowRight, UserCheck, ShieldCheck, Settings } from "lucide-react";
import { api, setAuthToken } from "../services/api";
import { DEMO_ROLE_OPTIONS } from "../utils/rbac";

const DEMO_ICONS = {
  user: User,
  approver: UserCheck,
  admin: Settings,
};

export default function LoginModal({ onLoginSuccess }) {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [loading, setLoading] = useState(false);
  const [demoLoadingRole, setDemoLoadingRole] = useState(null);
  const [error, setError] = useState(null);

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError(null);
    setLoading(true);

    try {
      const data = await api.login(username, password);
      setAuthToken(data.access_token);
      onLoginSuccess({
        id: data.user_id,
        username: data.username,
        role: data.role,
        is_demo: Boolean(data.is_demo),
        token: data.access_token,
      });
    } catch (err) {
      setError(err.message || "Invalid username or password.");
    } finally {
      setLoading(false);
    }
  };

  const handleDemoLogin = async (demoRoleKey) => {
    setError(null);
    setDemoLoadingRole(demoRoleKey);

    try {
      const data = await api.demoLogin(demoRoleKey);
      setAuthToken(data.access_token);
      onLoginSuccess({
        id: data.user_id,
        username: data.username,
        role: data.role,
        is_demo: Boolean(data.is_demo),
        token: data.access_token,
      });
    } catch (err) {
      setError(err.message || "Unable to start demo session.");
    } finally {
      setDemoLoadingRole(null);
    }
  };

  const busy = loading || Boolean(demoLoadingRole);

  return (
    <div
      style={{
        position: "fixed",
        inset: 0,
        backgroundColor: "rgba(15, 23, 42, 0.72)",
        backdropFilter: "blur(3px)",
        display: "flex",
        alignItems: "center",
        justifyContent: "center",
        zIndex: 1000,
        padding: "1rem",
        overflowY: "auto",
      }}
    >
      <div
        style={{
          backgroundColor: "#ffffff",
          borderRadius: "8px",
          width: "100%",
          maxWidth: "460px",
          boxShadow: "0 20px 25px -5px rgba(0, 0, 0, 0.12), 0 8px 10px -6px rgba(0, 0, 0, 0.08)",
          border: "1px solid #e2e8f0",
          overflow: "hidden",
        }}
      >
        {/* Header */}
        <div
          style={{
            padding: "1.25rem 1.5rem",
            borderBottom: "1px solid #e2e8f0",
            backgroundColor: "#f8fafc",
          }}
        >
          <div style={{ display: "flex", alignItems: "center", gap: "0.75rem" }}>
            <div
              style={{
                width: "36px",
                height: "36px",
                borderRadius: "6px",
                backgroundColor: "#0f172a",
                display: "flex",
                alignItems: "center",
                justifyContent: "center",
                color: "#ffffff",
                flexShrink: 0,
              }}
            >
              <Shield size={19} />
            </div>
            <div>
              <h2 style={{ fontSize: "1.0625rem", fontWeight: "600", color: "#0f172a", margin: 0 }}>
                AI Action Gateway
              </h2>
              <span style={{ fontSize: "0.75rem", color: "#475569" }}>
                Sign in with your account or launch an isolated role demo
              </span>
            </div>
          </div>
        </div>

        {/* Standard Login Form */}
        <form onSubmit={handleSubmit} style={{ padding: "1.25rem 1.5rem" }}>
          {error && (
            <div
              style={{
                display: "flex",
                alignItems: "flex-start",
                gap: "0.5rem",
                padding: "0.75rem",
                backgroundColor: "#fef2f2",
                border: "1px solid #fecaca",
                borderRadius: "6px",
                color: "#991b1b",
                fontSize: "0.8125rem",
                marginBottom: "1rem",
              }}
            >
              <AlertCircle size={16} style={{ flexShrink: 0, marginTop: "2px" }} />
              <div>{error}</div>
            </div>
          )}

          <div style={{ marginBottom: "0.875rem" }}>
            <label
              htmlFor="login-username"
              style={{ display: "block", fontSize: "0.8125rem", fontWeight: "500", color: "#334155", marginBottom: "0.375rem" }}
            >
              Username
            </label>
            <div style={{ position: "relative" }}>
              <User
                size={15}
                style={{ position: "absolute", left: "0.75rem", top: "50%", transform: "translateY(-50%)", color: "#94a3b8" }}
              />
              <input
                id="login-username"
                type="text"
                required
                autoComplete="username"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                placeholder="Enter username"
                style={{
                  width: "100%",
                  padding: "0.5rem 0.75rem 0.5rem 2.25rem",
                  fontSize: "0.875rem",
                  border: "1px solid #cbd5e1",
                  borderRadius: "6px",
                  outline: "none",
                  boxSizing: "border-box",
                }}
              />
            </div>
          </div>

          <div style={{ marginBottom: "1rem" }}>
            <label
              htmlFor="login-password"
              style={{ display: "block", fontSize: "0.8125rem", fontWeight: "500", color: "#334155", marginBottom: "0.375rem" }}
            >
              Password
            </label>
            <div style={{ position: "relative" }}>
              <Lock
                size={15}
                style={{ position: "absolute", left: "0.75rem", top: "50%", transform: "translateY(-50%)", color: "#94a3b8" }}
              />
              <input
                id="login-password"
                type="password"
                required
                autoComplete="current-password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder="Enter password"
                style={{
                  width: "100%",
                  padding: "0.5rem 0.75rem 0.5rem 2.25rem",
                  fontSize: "0.875rem",
                  border: "1px solid #cbd5e1",
                  borderRadius: "6px",
                  outline: "none",
                  boxSizing: "border-box",
                }}
              />
            </div>
          </div>

          <button
            type="submit"
            disabled={busy}
            style={{
              width: "100%",
              padding: "0.6rem 1rem",
              backgroundColor: "#0f172a",
              color: "#ffffff",
              border: "none",
              borderRadius: "6px",
              fontSize: "0.875rem",
              fontWeight: "500",
              cursor: busy ? "not-allowed" : "pointer",
              opacity: busy ? 0.7 : 1,
              display: "flex",
              alignItems: "center",
              justifyContent: "center",
              gap: "0.5rem",
            }}
          >
            {loading ? (
              "Signing in..."
            ) : (
              <>
                <span>Sign In</span>
                <ArrowRight size={15} />
              </>
            )}
          </button>
        </form>

        {/* Recruiter Demo Section */}
        <div
          style={{
            padding: "1.125rem 1.5rem 1.375rem",
            borderTop: "1px solid #e2e8f0",
            backgroundColor: "#f8fafc",
          }}
        >
          <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: "0.375rem" }}>
            <div style={{ display: "flex", alignItems: "center", gap: "0.375rem" }}>
              <ShieldCheck size={15} color="#0f172a" />
              <span style={{ fontSize: "0.8125rem", fontWeight: "600", color: "#0f172a" }}>
                Try Demo
              </span>
            </div>
            <span
              style={{
                fontSize: "0.6875rem",
                fontWeight: "600",
                color: "#475569",
                backgroundColor: "#e2e8f0",
                padding: "2px 6px",
                borderRadius: "4px",
                textTransform: "uppercase",
              }}
            >
              Isolated Sandbox
            </span>
          </div>

          <p style={{ fontSize: "0.75rem", color: "#475569", margin: "0 0 0.75rem", lineHeight: 1.4 }}>
            Explore all three role-based dashboards with fictional sample data. Demo sessions use signed tokens, cannot access production records, and never call external APIs.
          </p>

          <div style={{ display: "flex", flexDirection: "column", gap: "0.5rem" }}>
            {DEMO_ROLE_OPTIONS.map((opt) => {
              const Icon = DEMO_ICONS[opt.key] || User;
              const isLoadingThis = demoLoadingRole === opt.key;
              return (
                <button
                  key={opt.key}
                  type="button"
                  disabled={busy}
                  onClick={() => handleDemoLogin(opt.key)}
                  style={{
                    width: "100%",
                    textAlign: "left",
                    padding: "0.625rem 0.75rem",
                    backgroundColor: "#ffffff",
                    border: "1px solid #cbd5e1",
                    borderRadius: "6px",
                    cursor: busy ? "not-allowed" : "pointer",
                    opacity: busy && !isLoadingThis ? 0.65 : 1,
                    display: "flex",
                    alignItems: "center",
                    justifyContent: "space-between",
                    gap: "0.75rem",
                  }}
                >
                  <div style={{ display: "flex", alignItems: "flex-start", gap: "0.625rem" }}>
                    <Icon size={16} color="#0f172a" style={{ marginTop: "2px", flexShrink: 0 }} />
                    <div>
                      <div style={{ fontSize: "0.8125rem", fontWeight: "600", color: "#0f172a" }}>
                        {isLoadingThis ? `Signing in as Demo ${opt.shortLabel}...` : opt.label}
                      </div>
                      <div style={{ fontSize: "0.71875rem", color: "#64748b", marginTop: "1px" }}>
                        {opt.description}
                      </div>
                    </div>
                  </div>
                  <ArrowRight size={14} color="#64748b" style={{ flexShrink: 0 }} />
                </button>
              );
            })}
          </div>
        </div>
      </div>
    </div>
  );
}
