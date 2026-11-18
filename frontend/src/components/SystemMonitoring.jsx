import React, { useState, useEffect } from "react";
import { ShieldCheck, AlertTriangle, RefreshCw } from "lucide-react";
import { api } from "../services/api";

export function SystemMonitoring() {
  const [metrics, setMetrics] = useState(null);
  const [healthOk, setHealthOk] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  const fetchMetrics = async () => {
    setLoading(true);
    setError(null);
    try {
      const [health, data] = await Promise.all([
        api.checkHealth().then(() => true).catch(() => false),
        api.getMetrics(),
      ]);
      setHealthOk(health);
      setMetrics(data);
    } catch (err) {
      setError(err.message || "Failed to load system telemetry.");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchMetrics();
    const interval = setInterval(fetchMetrics, 15000);
    return () => clearInterval(interval);
  }, []);

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 20 }}>
      <div className="panel">
        <div className="panel-header">
          <div>
            <h2 className="panel-title">System Monitoring</h2>
            <p className="panel-subtitle">
              Live gateway health, database connectivity, and request volume telemetry
            </p>
          </div>
          <button className="btn btn-secondary btn-sm" onClick={fetchMetrics} disabled={loading}>
            <RefreshCw size={13} />
            <span>Refresh</span>
          </button>
        </div>

        <div className="panel-body">
          {error && (
            <div className="alert-banner error" style={{ marginBottom: 16 }}>
              <AlertTriangle size={15} />
              <span>{error}</span>
            </div>
          )}

          <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(190px, 1fr))", gap: 16, marginBottom: 24 }}>
            <div style={{ padding: 16, borderRadius: 6, border: "1px solid var(--border-subtle)", backgroundColor: "var(--bg-app)" }}>
              <span style={{ fontSize: 11, fontWeight: 600, color: "var(--text-muted)", textTransform: "uppercase" }}>
                Backend Health
              </span>
              <div style={{ display: "flex", alignItems: "center", gap: 8, marginTop: 8 }}>
                <span className={`status-dot ${healthOk === false ? "error" : ""}`}></span>
                <strong style={{ fontSize: 15 }}>
                  {healthOk === null ? "Checking..." : healthOk ? "Operational" : "Degraded"}
                </strong>
              </div>
            </div>

            <div style={{ padding: 16, borderRadius: 6, border: "1px solid var(--border-subtle)", backgroundColor: "var(--bg-app)" }}>
              <span style={{ fontSize: 11, fontWeight: 600, color: "var(--text-muted)", textTransform: "uppercase" }}>
                Environment
              </span>
              <div style={{ fontSize: 15, fontWeight: 700, marginTop: 8 }}>
                {metrics ? metrics.app_env.toUpperCase() : "—"}
              </div>
            </div>

            <div style={{ padding: 16, borderRadius: 6, border: "1px solid var(--border-subtle)", backgroundColor: "var(--bg-app)" }}>
              <span style={{ fontSize: 11, fontWeight: 600, color: "var(--text-muted)", textTransform: "uppercase" }}>
                Registered APIs
              </span>
              <div style={{ fontSize: 15, fontWeight: 700, marginTop: 8 }}>
                {metrics ? metrics.total_apis : "—"}
              </div>
            </div>

            <div style={{ padding: 16, borderRadius: 6, border: "1px solid var(--border-subtle)", backgroundColor: "var(--bg-app)" }}>
              <span style={{ fontSize: 11, fontWeight: 600, color: "var(--text-muted)", textTransform: "uppercase" }}>
                User Accounts
              </span>
              <div style={{ fontSize: 15, fontWeight: 700, marginTop: 8 }}>
                {metrics ? metrics.total_users : "—"}
              </div>
            </div>

            <div style={{ padding: 16, borderRadius: 6, border: "1px solid var(--border-subtle)", backgroundColor: "var(--bg-app)" }}>
              <span style={{ fontSize: 11, fontWeight: 600, color: "var(--text-muted)", textTransform: "uppercase" }}>
                Pending Approvals
              </span>
              <div style={{ fontSize: 15, fontWeight: 700, marginTop: 8 }}>
                {metrics ? metrics.pending_approvals : "—"}
              </div>
            </div>

            <div style={{ padding: 16, borderRadius: 6, border: "1px solid var(--border-subtle)", backgroundColor: "var(--bg-app)" }}>
              <span style={{ fontSize: 11, fontWeight: 600, color: "var(--text-muted)", textTransform: "uppercase" }}>
                Total Executions
              </span>
              <div style={{ fontSize: 15, fontWeight: 700, marginTop: 8 }}>
                {metrics ? metrics.total_executions : "—"}
              </div>
            </div>
          </div>

          <h3 style={{ fontSize: 14, fontWeight: 600, marginBottom: 12 }}>Active Runtime Protections</h3>
          <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(260px, 1fr))", gap: 12 }}>
            <div style={{ padding: "12px 14px", borderRadius: 6, backgroundColor: "var(--bg-app)", border: "1px solid var(--border-subtle)", display: "flex", gap: 10, alignItems: "center" }}>
              <ShieldCheck size={18} color="#059669" />
              <div>
                <strong style={{ fontSize: 13, display: "block" }}>DNS Pinning Transport</strong>
                <span style={{ fontSize: 11, color: "var(--text-muted)" }}>Prevents DNS rebinding on external calls</span>
              </div>
            </div>

            <div style={{ padding: "12px 14px", borderRadius: 6, backgroundColor: "var(--bg-app)", border: "1px solid var(--border-subtle)", display: "flex", gap: 10, alignItems: "center" }}>
              <ShieldCheck size={18} color="#059669" />
              <div>
                <strong style={{ fontSize: 13, display: "block" }}>SSRF Boundary Enforcement</strong>
                <span style={{ fontSize: 11, color: "var(--text-muted)" }}>Blocks private, loopback, and metadata hosts</span>
              </div>
            </div>

            <div style={{ padding: "12px 14px", borderRadius: 6, backgroundColor: "var(--bg-app)", border: "1px solid var(--border-subtle)", display: "flex", gap: 10, alignItems: "center" }}>
              <ShieldCheck size={18} color="#059669" />
              <div>
                <strong style={{ fontSize: 13, display: "block" }}>Brute-Force Rate Limiting</strong>
                <span style={{ fontSize: 11, color: "var(--text-muted)" }}>Database-backed lockout + burst throttle</span>
              </div>
            </div>

            <div style={{ padding: "12px 14px", borderRadius: 6, backgroundColor: "var(--bg-app)", border: "1px solid var(--border-subtle)", display: "flex", gap: 10, alignItems: "center" }}>
              <ShieldCheck size={18} color="#059669" />
              <div>
                <strong style={{ fontSize: 13, display: "block" }}>Four-Eyes Approval Enforcement</strong>
                <span style={{ fontSize: 11, color: "var(--text-muted)" }}>Blocks self-approval across all roles</span>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
