import React from "react";
import { Sliders, Lock, Shield, Globe, Key } from "lucide-react";

export function Settings() {
  return (
    <div style={{ display: "flex", flexDirection: "column", gap: "20px" }}>
      <div className="panel">
        <div className="panel-header">
          <div>
            <h2 className="panel-title">Gateway System Configuration</h2>
            <p className="panel-subtitle">Production security parameters, tokens, and network boundaries</p>
          </div>
        </div>

        <div className="panel-body">
          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "20px" }}>
            {/* JWT Parameters */}
            <div style={{ padding: "16px", borderRadius: "8px", border: "1px solid var(--border)", backgroundColor: "var(--bg-main)" }}>
              <div style={{ display: "flex", alignItems: "center", gap: "8px", marginBottom: "12px" }}>
                <Key size={16} color="var(--primary)" />
                <strong style={{ fontSize: "14px" }}>JWT &amp; Authentication Standards</strong>
              </div>
              <table style={{ width: "100%", fontSize: "12px", borderCollapse: "collapse" }}>
                <tbody>
                  <tr style={{ borderBottom: "1px solid var(--border)" }}>
                    <td style={{ padding: "6px 0", color: "var(--text-muted)" }}>Signature Algorithm</td>
                    <td style={{ padding: "6px 0", textAlign: "right", fontWeight: "600" }}>HS256 (Pinned)</td>
                  </tr>
                  <tr style={{ borderBottom: "1px solid var(--border)" }}>
                    <td style={{ padding: "6px 0", color: "var(--text-muted)" }}>Token Expiry</td>
                    <td style={{ padding: "6px 0", textAlign: "right", fontWeight: "600" }}>15 Minutes</td>
                  </tr>
                  <tr style={{ borderBottom: "1px solid var(--border)" }}>
                    <td style={{ padding: "6px 0", color: "var(--text-muted)" }}>Token Issuer (iss)</td>
                    <td style={{ padding: "6px 0", textAlign: "right", fontWeight: "600" }}>guardrailed-ai-gateway</td>
                  </tr>
                  <tr>
                    <td style={{ padding: "6px 0", color: "var(--text-muted)" }}>Token Audience (aud)</td>
                    <td style={{ padding: "6px 0", textAlign: "right", fontWeight: "600" }}>guardrailed-ai-gateway-api</td>
                  </tr>
                </tbody>
              </table>
            </div>

            {/* Network & CORS Parameters */}
            <div style={{ padding: "16px", borderRadius: "8px", border: "1px solid var(--border)", backgroundColor: "var(--bg-main)" }}>
              <div style={{ display: "flex", alignItems: "center", gap: "8px", marginBottom: "12px" }}>
                <Globe size={16} color="#0284c7" />
                <strong style={{ fontSize: "14px" }}>Network &amp; Isolation Boundaries</strong>
              </div>
              <table style={{ width: "100%", fontSize: "12px", borderCollapse: "collapse" }}>
                <tbody>
                  <tr style={{ borderBottom: "1px solid var(--border)" }}>
                    <td style={{ padding: "6px 0", color: "var(--text-muted)" }}>CORS Whitelist</td>
                    <td style={{ padding: "6px 0", textAlign: "right", fontWeight: "600" }}>ai-action-orchestration-gateway.vercel.app</td>
                  </tr>
                  <tr style={{ borderBottom: "1px solid var(--border)" }}>
                    <td style={{ padding: "6px 0", color: "var(--text-muted)" }}>External Transport</td>
                    <td style={{ padding: "6px 0", textAlign: "right", fontWeight: "600" }}>Custom PinnedTransport (DNS Pinning)</td>
                  </tr>
                  <tr style={{ borderBottom: "1px solid var(--border)" }}>
                    <td style={{ padding: "6px 0", color: "var(--text-muted)" }}>Redirect Policy</td>
                    <td style={{ padding: "6px 0", textAlign: "right", fontWeight: "600" }}>follow_redirects=False (Strict)</td>
                  </tr>
                  <tr>
                    <td style={{ padding: "6px 0", color: "var(--text-muted)" }}>Database Storage</td>
                    <td style={{ padding: "6px 0", textAlign: "right", fontWeight: "600" }}>PostgreSQL 16 (Render Managed)</td>
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
