import React, { useState, useEffect } from "react";
import { ShieldCheck, Lock, RefreshCw, AlertCircle } from "lucide-react";
import { api } from "../services/api";

const POLICIES = [
  {
    name: "Four-Eyes Principle (Anti-Self-Approval)",
    scope: "POST /approvals/{id}/approve",
    description:
      "Requesters cannot approve their own sensitive operations, including Administrators. A second authorized Approver or Admin is required.",
    status: "Enforced",
  },
  {
    name: "Admin Sensitive-Action No-Bypass Rule",
    scope: "POST /tasks",
    description:
      "Sensitive or destructive operations submitted by an Admin still halt in the approval queue (HTTP 202) and cannot auto-execute.",
    status: "Enforced",
  },
  {
    name: "Immutable Frozen Payload Binding",
    scope: "approval_requests.request_payload",
    description:
      "Approved executions dispatch the exact validated operation and payload persisted at submission time. Post-approval tampering is ignored.",
    status: "Enforced",
  },
  {
    name: "User Response Sanitization",
    scope: "/tasks, /approvals/my, /logs, /apis/tools",
    description:
      "Backend serializers strip endpoint paths, HTTP methods, raw payloads, credentials, and internal classification reasoning from User responses.",
    status: "Enforced",
  },
  {
    name: "Ownership & IDOR Isolation",
    scope: "GET /approvals/{id}, GET /logs/{id}",
    description:
      "Users can only access records they created. Cross-user access attempts return HTTP 403. Approvers are restricted to approval-linked or failed logs.",
    status: "Enforced",
  },
  {
    name: "Last-Admin Account Protection",
    scope: "PATCH /auth/users/{id}",
    description:
      "Prevents demoting or deactivating the final active administrator account to avoid administrative lockout.",
    status: "Enforced",
  },
  {
    name: "SSRF & DNS Pinning Transport",
    scope: "External API Executor",
    description:
      "Blocks private IP ranges, loopback, and cloud metadata endpoints, disables redirects, and binds outbound connections to verified resolved IPs.",
    status: "Enforced",
  },
  {
    name: "Credential Encryption at Rest",
    scope: "api_registry.auth_header_value",
    description:
      "External API secrets are encrypted with Fernet symmetric encryption before database persistence and never serialized to API responses.",
    status: "Enforced",
  },
];

export function SecurityPolicies() {
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
      setError(err.message || "Failed to load security policy telemetry.");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchMetrics();
  }, []);

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 20 }}>
      <div className="panel">
        <div className="panel-header">
          <div>
            <h2 className="panel-title">Security &amp; Guardrail Policies</h2>
            <p className="panel-subtitle">
              Active backend enforcement controls governing authentication, authorization, and API dispatch
            </p>
          </div>
          <button className="btn btn-secondary btn-sm" onClick={fetchMetrics} disabled={loading}>
            <RefreshCw size={13} />
            <span>Refresh</span>
          </button>
        </div>

        <div className="panel-body" style={{ padding: 0 }}>
          {error && (
            <div style={{ padding: "16px 20px 0" }}>
              <div className="alert-banner error">
                <AlertCircle size={15} />
                <span>{error}</span>
              </div>
            </div>
          )}

          <div className="table-responsive">
            <table className="data-table">
              <thead>
                <tr>
                  <th>Security Policy</th>
                  <th>Enforcement Surface</th>
                  <th>Behavior</th>
                  <th style={{ textAlign: "right" }}>State</th>
                </tr>
              </thead>
              <tbody>
                {POLICIES.map((p) => (
                  <tr key={p.name}>
                    <td style={{ fontWeight: 600, fontSize: 13 }}>{p.name}</td>
                    <td>
                      <code style={{ fontFamily: "var(--font-mono)", fontSize: 11 }}>{p.scope}</code>
                    </td>
                    <td style={{ fontSize: 12, color: "var(--text-muted)", maxWidth: 420 }}>
                      {p.description}
                    </td>
                    <td style={{ textAlign: "right" }}>
                      <span className="badge badge-safe">
                        <ShieldCheck size={11} />
                        <span>{p.status}</span>
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      </div>

      {metrics && (
        <div className="panel" style={{ padding: 20 }}>
          <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 12 }}>
            <Lock size={15} color="var(--primary)" />
            <h3 style={{ fontSize: 14, fontWeight: 600, margin: 0 }}>Active Token &amp; Session Policy</h3>
          </div>
          <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(220px, 1fr))", gap: 12, fontSize: 12 }}>
            <div style={{ padding: 12, borderRadius: 6, border: "1px solid var(--border-subtle)", backgroundColor: "var(--bg-app)" }}>
              <div style={{ color: "var(--text-muted)" }}>JWT Expiry Window</div>
              <div style={{ fontWeight: 600, fontSize: 14, marginTop: 4 }}>{metrics.jwt_expire_minutes} minutes</div>
            </div>
            <div style={{ padding: 12, borderRadius: 6, border: "1px solid var(--border-subtle)", backgroundColor: "var(--bg-app)" }}>
              <div style={{ color: "var(--text-muted)" }}>Token Issuer</div>
              <div style={{ fontWeight: 600, fontSize: 13, marginTop: 4, fontFamily: "var(--font-mono)" }}>{metrics.jwt_issuer}</div>
            </div>
            <div style={{ padding: 12, borderRadius: 6, border: "1px solid var(--border-subtle)", backgroundColor: "var(--bg-app)" }}>
              <div style={{ color: "var(--text-muted)" }}>Token Audience</div>
              <div style={{ fontWeight: 600, fontSize: 13, marginTop: 4, fontFamily: "var(--font-mono)" }}>{metrics.jwt_audience}</div>
            </div>
            <div style={{ padding: 12, borderRadius: 6, border: "1px solid var(--border-subtle)", backgroundColor: "var(--bg-app)" }}>
              <div style={{ color: "var(--text-muted)" }}>Login Brute-Force Lockout</div>
              <div style={{ fontWeight: 600, fontSize: 14, marginTop: 4 }}>5 failures / 5 min</div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
