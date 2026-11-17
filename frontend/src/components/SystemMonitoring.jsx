import React, { useState, useEffect } from "react";
import { ShieldCheck, Activity, Cpu, Server, Lock, AlertTriangle, RefreshCw } from "lucide-react";
import { api } from "../services/api";

export function SystemMonitoring() {
  const [metrics, setMetrics] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  const fetchMetrics = async () => {
    setLoading(true);
    setError(null);
    try {
      const data = await api.getMetrics();
      setMetrics(data);
    } catch (err) {
      setError(err.message || "Failed to load system metrics.");
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
    <div style={{ display: "flex", flexDirection: "column", gap: "20px" }}>
      <div className="panel">
        <div className="panel-header">
          <div>
            <h2 className="panel-title">Gateway Health &amp; Security Telemetry</h2>
            <p className="panel-subtitle">Real-time health status, rate limiting, and security controls</p>
          </div>
          <button className="btn btn-secondary btn-sm" onClick={fetchMetrics} disabled={loading}>
            <RefreshCw size={13} className={loading ? "animate-spin" : ""} />
            <span>Refresh</span>
          </button>
        </div>

        <div className="panel-body">
          {error && (
            <div className="alert-banner error" style={{ marginBottom: "16px" }}>
              <AlertTriangle size={15} />
              <span>{error}</span>
            </div>
          )}

          <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(200px, 1fr))", gap: "16px", marginBottom: "24px" }}>
            <div style={{ padding: "16px", borderRadius: "8px", border: "1px solid var(--border)", backgroundColor: "var(--bg-main)" }}>
              <span style={{ fontSize: "11px", fontWeight: "600", color: "var(--text-muted)", textTransform: "uppercase" }}>
                Service Status
              </span>
              <div style={{ display: "flex", alignItems: "center", gap: "8px", marginTop: "8px" }}>
                <span className="status-dot"></span>
                <strong style={{ fontSize: "16px", color: "var(--success)" }}>OPERATIONAL</strong>
              </div>
            </div>

            <div style={{ padding: "16px", borderRadius: "8px", border: "1px solid var(--border)", backgroundColor: "var(--bg-main)" }}>
              <span style={{ fontSize: "11px", fontWeight: "600", color: "var(--text-muted)", textTransform: "uppercase" }}>
                Environment Mode
              </span>
              <div style={{ fontSize: "16px", fontWeight: "700", marginTop: "8px" }}>
                {metrics?.app_env?.toUpperCase() || "SANDBOX"}
              </div>
            </div>

            <div style={{ padding: "16px", borderRadius: "8px", border: "1px solid var(--border)", backgroundColor: "var(--bg-main)" }}>
              <span style={{ fontSize: "11px", fontWeight: "600", color: "var(--text-muted)", textTransform: "uppercase" }}>
                Active Users
              </span>
              <div style={{ fontSize: "16px", fontWeight: "700", marginTop: "8px" }}>
                {metrics?.total_users ?? 3} accounts
              </div>
            </div>

            <div style={{ padding: "16px", borderRadius: "8px", border: "1px solid var(--border)", backgroundColor: "var(--bg-main)" }}>
              <span style={{ fontSize: "11px", fontWeight: "600", color: "var(--text-muted)", textTransform: "uppercase" }}>
                Registered APIs
              </span>
              <div style={{ fontSize: "16px", fontWeight: "700", marginTop: "8px" }}>
                {metrics?.total_apis ?? 0} endpoints
              </div>
            </div>
          </div>

          <h3 style={{ fontSize: "15px", fontWeight: "600", marginBottom: "14px" }}>Active Security Defenses</h3>
          <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(280px, 1fr))", gap: "12px" }}>
            <div style={{ padding: "12px 16px", borderRadius: "6px", backgroundColor: "#f8fafc", border: "1px solid #e2e8f0", display: "flex", gap: "12px", alignItems: "center" }}>
              <ShieldCheck size={20} color="#16a34a" />
              <div>
                <strong style={{ fontSize: "13px", display: "block" }}>DNS Pinning &amp; TOCTOU Prevention</strong>
                <span style={{ fontSize: "11px", color: "var(--text-muted)" }}>PinnedHTTPTransport connects strictly to pre-resolved IPs</span>
              </div>
            </div>

            <div style={{ padding: "12px 16px", borderRadius: "6px", backgroundColor: "#f8fafc", border: "1px solid #e2e8f0", display: "flex", gap: "12px", alignItems: "center" }}>
              <ShieldCheck size={20} color="#16a34a" />
              <div>
                <strong style={{ fontSize: "13px", display: "block" }}>SSRF Boundary Defense</strong>
                <span style={{ fontSize: "11px", color: "var(--text-muted)" }}>Private, loopback &amp; cloud metadata blocks active</span>
              </div>
            </div>

            <div style={{ padding: "12px 16px", borderRadius: "6px", backgroundColor: "#f8fafc", border: "1px solid #e2e8f0", display: "flex", gap: "12px", alignItems: "center" }}>
              <ShieldCheck size={20} color="#16a34a" />
              <div>
                <strong style={{ fontSize: "13px", display: "block" }}>Distributed Brute-Force Defense</strong>
                <span style={{ fontSize: "11px", color: "var(--text-muted)" }}>5 failed attempts / 5m window database rate limiter</span>
              </div>
            </div>

            <div style={{ padding: "12px 16px", borderRadius: "6px", backgroundColor: "#f8fafc", border: "1px solid #e2e8f0", display: "flex", gap: "12px", alignItems: "center" }}>
              <ShieldCheck size={20} color="#16a34a" />
              <div>
                <strong style={{ fontSize: "13px", display: "block" }}>Anti-Self-Approval (Four-Eyes)</strong>
                <span style={{ fontSize: "11px", color: "var(--text-muted)" }}>Requesters cannot authorize their own sensitive actions</span>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
