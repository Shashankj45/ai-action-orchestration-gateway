import React, { useState } from "react";
import { Shield, Lock, User, AlertCircle, ArrowRight } from "lucide-react";
import { api, setAuthToken } from "../services/api";

export default function LoginModal({ onLoginSuccess }) {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError(null);
    setLoading(true);

    try {
      const data = await api.login(username, password);
      // Store token exclusively in in-memory state
      setAuthToken(data.access_token);
      onLoginSuccess({
        id: data.user_id,
        username: data.username,
        role: data.role,
        token: data.access_token,
      });
    } catch (err) {
      setError(err.message || "Invalid username or password.");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div style={{
      position: "fixed",
      inset: 0,
      backgroundColor: "rgba(15, 23, 42, 0.75)",
      backdropFilter: "blur(4px)",
      display: "flex",
      alignItems: "center",
      justifyContent: "center",
      zIndex: 1000,
      padding: "1rem",
    }}>
      <div style={{
        backgroundColor: "#ffffff",
        borderRadius: "8px",
        width: "100%",
        maxWidth: "420px",
        boxShadow: "0 20px 25px -5px rgba(0, 0, 0, 0.1), 0 8px 10px -6px rgba(0, 0, 0, 0.1)",
        border: "1px solid #e2e8f0",
        overflow: "hidden",
      }}>
        {/* Header */}
        <div style={{
          padding: "1.5rem 1.5rem 1rem 1.5rem",
          borderBottom: "1px solid #f1f5f9",
          backgroundColor: "#f8fafc",
        }}>
          <div style={{ display: "flex", alignItems: "center", gap: "0.75rem", marginBottom: "0.25rem" }}>
            <div style={{
              width: "36px",
              height: "36px",
              borderRadius: "6px",
              backgroundColor: "#1e293b",
              display: "flex",
              alignItems: "center",
              justifyContent: "center",
              color: "#ffffff",
            }}>
              <Shield size={20} />
            </div>
            <div>
              <h2 style={{ fontSize: "1.125rem", fontWeight: "600", color: "#0f172a", margin: 0 }}>
                Gateway Authentication
              </h2>
              <span style={{ fontSize: "0.75rem", color: "#64748b" }}>
                Zero-Trust Inbound RBAC Access
              </span>
            </div>
          </div>
        </div>

        {/* Form Body */}
        <form onSubmit={handleSubmit} style={{ padding: "1.5rem" }}>
          {error && (
            <div style={{
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
            }}>
              <AlertCircle size={16} style={{ flexShrink: 0, marginTop: "2px" }} />
              <div>{error}</div>
            </div>
          )}

          <div style={{ marginBottom: "1rem" }}>
            <label style={{ display: "block", fontSize: "0.8125rem", fontWeight: "500", color: "#334155", marginBottom: "0.375rem" }}>
              Username
            </label>
            <div style={{ position: "relative" }}>
              <User size={16} style={{ position: "absolute", left: "0.75rem", top: "50%", transform: "translateY(-50%)", color: "#94a3b8" }} />
              <input
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

          <div style={{ marginBottom: "1.25rem" }}>
            <label style={{ display: "block", fontSize: "0.8125rem", fontWeight: "500", color: "#334155", marginBottom: "0.375rem" }}>
              Password
            </label>
            <div style={{ position: "relative" }}>
              <Lock size={16} style={{ position: "absolute", left: "0.75rem", top: "50%", transform: "translateY(-50%)", color: "#94a3b8" }} />
              <input
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
            disabled={loading}
            style={{
              width: "100%",
              padding: "0.625rem 1rem",
              backgroundColor: "#1e293b",
              color: "#ffffff",
              border: "none",
              borderRadius: "6px",
              fontSize: "0.875rem",
              fontWeight: "500",
              cursor: loading ? "not-allowed" : "pointer",
              opacity: loading ? 0.7 : 1,
              display: "flex",
              alignItems: "center",
              justifyContent: "center",
              gap: "0.5rem",
            }}
          >
            {loading ? "Authenticating..." : (
              <>
                Sign In to Gateway <ArrowRight size={16} />
              </>
            )}
          </button>
        </form>
      </div>
    </div>
  );
}
