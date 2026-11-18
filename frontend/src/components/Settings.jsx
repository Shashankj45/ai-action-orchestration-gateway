import React, { useState, useEffect } from "react";
import { Globe, Key, RefreshCw, AlertCircle } from "lucide-react";
import { api } from "../services/api";

export function Settings() {
  const [metrics, setMetrics] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  const fetchSettings = async () => {
    setLoading(true);
    setError(null);
    try {
      const data = await api.getMetrics();
      setMetrics(data);
    } catch (err) {
      setError(err.message || "Failed to retrieve gateway configuration.");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchSettings();
  }, []);

  const originsList = Array.isArray(metrics?.allowed_origins)
    ? metrics.allowed_origins.join(", ")
    : "—";

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 20 }}>
      <div className="panel">
        <div className="panel-header">
          <div>
            <h2 className="panel-title">Gateway Settings</h2>
            <p className="panel-subtitle">
              Live authentication, network boundary, and runtime environment configuration
            </p>
          </div>
          <button className="btn btn-secondary btn-sm" onClick={fetchSettings} disabled={loading}>
            <RefreshCw size={13} />
            <span>Refresh</span>
          </button>
        </div>

        <div className="panel-body">
          {error && (
            <div className="alert-banner error" style={{ marginBottom: 16 }}>
              <AlertCircle size={15} />
              <span>{error}</span>
            </div>
          )}

          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 20 }}>
            {/* JWT Parameters */}
            <div style={{ padding: 16, borderRadius: 6, border: "1px solid var(--border-subtle)", backgroundColor: "var(--bg-app)" }}>
              <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 12 }}>
                <Key size={15} color="var(--primary)" />
                <strong style={{ fontSize: 14 }}>Authentication &amp; Token Configuration</strong>
              </div>
              <table style={{ width: "100%", fontSize: 12, borderCollapse: "collapse" }}>
                <tbody>
                  <tr style={{ borderBottom: "1px solid var(--border-subtle)" }}>
                    <td style={{ padding: "8px 0", color: "var(--text-muted)" }}>Signature Algorithm</td>
                    <td style={{ padding: "8px 0", textAlign: "right", fontWeight: 600 }}>HS256 (Pinned)</td>
                  </tr>
                  <tr style={{ borderBottom: "1px solid var(--border-subtle)" }}>
                    <td style={{ padding: "8px 0", color: "var(--text-muted)" }}>Access Token Lifetime</td>
                    <td style={{ padding: "8px 0", textAlign: "right", fontWeight: 600 }}>
                      {metrics ? `${metrics.jwt_expire_minutes} minutes` : "—"}
                    </td>
                  </tr>
                  <tr style={{ borderBottom: "1px solid var(--border-subtle)" }}>
                    <td style={{ padding: "8px 0", color: "var(--text-muted)" }}>Token Issuer (iss)</td>
                    <td style={{ padding: "8px 0", textAlign: "right", fontWeight: 600, fontFamily: "var(--font-mono)" }}>
                      {metrics?.jwt_issuer || "—"}
                    </td>
                  </tr>
                  <tr>
                    <td style={{ padding: "8px 0", color: "var(--text-muted)" }}>Token Audience (aud)</td>
                    <td style={{ padding: "8px 0", textAlign: "right", fontWeight: 600, fontFamily: "var(--font-mono)" }}>
                      {metrics?.jwt_audience || "—"}
                    </td>
                  </tr>
                </tbody>
              </table>
            </div>

            {/* Network & CORS Parameters */}
            <div style={{ padding: 16, borderRadius: 6, border: "1px solid var(--border-subtle)", backgroundColor: "var(--bg-app)" }}>
              <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 12 }}>
                <Globe size={15} color="#0284c7" />
                <strong style={{ fontSize: 14 }}>Network &amp; Boundary Configuration</strong>
              </div>
              <table style={{ width: "100%", fontSize: 12, borderCollapse: "collapse" }}>
                <tbody>
                  <tr style={{ borderBottom: "1px solid var(--border-subtle)" }}>
                    <td style={{ padding: "8px 0", color: "var(--text-muted)" }}>Runtime Environment</td>
                    <td style={{ padding: "8px 0", textAlign: "right", fontWeight: 600 }}>
                      {metrics?.app_env || "—"}
                    </td>
                  </tr>
                  <tr style={{ borderBottom: "1px solid var(--border-subtle)" }}>
                    <td style={{ padding: "8px 0", color: "var(--text-muted)" }}>Allowed Origins (CORS)</td>
                    <td style={{ padding: "8px 0", textAlign: "right", fontWeight: 600, wordBreak: "break-all" }}>
                      {originsList}
                    </td>
                  </tr>
                  <tr style={{ borderBottom: "1px solid var(--border-subtle)" }}>
                    <td style={{ padding: "8px 0", color: "var(--text-muted)" }}>Trusted Hosts</td>
                    <td style={{ padding: "8px 0", textAlign: "right", fontWeight: 600 }}>
                      {metrics?.allowed_hosts || "—"}
                    </td>
                  </tr>
                  <tr>
                    <td style={{ padding: "8px 0", color: "var(--text-muted)" }}>Outbound Redirect Policy</td>
                    <td style={{ padding: "8px 0", textAlign: "right", fontWeight: 600 }}>Disabled (Strict)</td>
                  </tr>
                </tbody>
              </table>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
