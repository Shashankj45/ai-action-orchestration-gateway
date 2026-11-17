import React from "react";
import { UserCheck, Shield, Key, LogOut } from "lucide-react";

export function Profile({ user, onSignOut }) {
  const getRoleDetails = (role) => {
    switch (role) {
      case "ADMIN":
        return {
          title: "Hotel IT Administrator",
          badgeBg: "#0f172a",
          badgeColor: "#f8fafc",
          description: "Full administrative governance: API integration, user provisioning, audit inspection, and system monitoring.",
          permissions: [
            "Register, update, and delete external hotel APIs",
            "Provision new user accounts and assign RBAC roles",
            "View company-wide audit trails and replay safe operations",
            "Monitor live health metrics and rate limiter state",
          ],
        };
      case "APPROVER":
        return {
          title: "Hotel Duty Manager / Supervisor",
          badgeBg: "#047857",
          badgeColor: "#ecfdf5",
          description: "Supervisor authority: reviews, approves, or rejects sensitive guest requests under Four-Eyes governance.",
          permissions: [
            "Inspect pending sensitive operations in real-time",
            "Authorize or reject guest room booking cancellations",
            "View approval history and manager decisions",
            "Cannot submit operational tasks (Separation of Duties)",
          ],
        };
      case "OPERATOR":
      default:
        return {
          title: "Hotel Guest / Customer (Requester)",
          badgeBg: "#1d4ed8",
          badgeColor: "#eff6ff",
          description: "Customer access: submits natural language booking requests and tracks request approval statuses.",
          permissions: [
            "Submit natural language requests via AI Task Console",
            "View reservation details (Safe auto-executed actions)",
            "Request room cancellations and late checkouts (held for manager approval)",
            "View own request tracking and personal execution history",
          ],
        };
    }
  };

  const details = getRoleDetails(user?.role);

  return (
    <div style={{ maxWidth: "680px", margin: "0 auto" }}>
      <div className="panel">
        <div className="panel-header">
          <div>
            <h2 className="panel-title">Authenticated Identity &amp; Role Profile</h2>
            <p className="panel-subtitle">Role permissions, identity attribution, and active session tokens</p>
          </div>
        </div>

        <div className="panel-body">
          <div style={{ display: "flex", alignItems: "center", gap: "16px", marginBottom: "24px" }}>
            <div
              style={{
                width: "56px",
                height: "56px",
                borderRadius: "50%",
                backgroundColor: details.badgeBg,
                color: details.badgeColor,
                display: "flex",
                alignItems: "center",
                justifyContent: "center",
                fontWeight: "700",
                fontSize: "20px",
              }}
            >
              {user?.username?.charAt(0).toUpperCase() || "U"}
            </div>
            <div>
              <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
                <h3 style={{ fontSize: "18px", fontWeight: "700", margin: 0 }}>{user?.username}</h3>
                <span
                  style={{
                    padding: "3px 8px",
                    borderRadius: "4px",
                    backgroundColor: details.badgeBg,
                    color: details.badgeColor,
                    fontSize: "11px",
                    fontWeight: "700",
                  }}
                >
                  {details.title}
                </span>
              </div>
              <p style={{ fontSize: "12px", color: "var(--text-muted)", margin: "4px 0 0" }}>
                User ID: <code>{user?.id}</code>
              </p>
            </div>
          </div>

          <div style={{ marginBottom: "20px" }}>
            <h4 style={{ fontSize: "13px", fontWeight: "600", marginBottom: "8px", textTransform: "uppercase", color: "var(--text-muted)" }}>
              Role Scope &amp; Responsibilities
            </h4>
            <p style={{ fontSize: "13px", color: "var(--text-main)", lineHeight: "1.5" }}>
              {details.description}
            </p>
          </div>

          <div style={{ marginBottom: "24px" }}>
            <h4 style={{ fontSize: "13px", fontWeight: "600", marginBottom: "8px", textTransform: "uppercase", color: "var(--text-muted)" }}>
              Authorized Permissions
            </h4>
            <ul style={{ margin: 0, paddingLeft: "18px", fontSize: "12px", color: "var(--text-muted)", display: "flex", flexDirection: "column", gap: "6px" }}>
              {details.permissions.map((perm, idx) => (
                <li key={idx} style={{ color: "var(--text-main)" }}>{perm}</li>
              ))}
            </ul>
          </div>

          <div style={{ padding: "16px", borderRadius: "8px", backgroundColor: "var(--bg-main)", border: "1px solid var(--border)", marginBottom: "20px" }}>
            <div style={{ display: "flex", alignItems: "center", gap: "8px", marginBottom: "8px" }}>
              <Key size={14} color="var(--primary)" />
              <strong style={{ fontSize: "12px" }}>Session &amp; Token Architecture</strong>
            </div>
            <p style={{ fontSize: "11px", color: "var(--text-dim)", margin: 0 }}>
              Session tokens are stored exclusively in in-memory React state to shield credentials from persistent XSS vector theft.
              Clicking <strong>Sign Out</strong> revokes this token immediately via server-side JTI denylist.
            </p>
          </div>

          <div style={{ display: "flex", justifyContent: "flex-end" }}>
            <button className="btn btn-secondary" onClick={onSignOut}>
              <LogOut size={14} />
              <span>Sign Out &amp; Revoke Token</span>
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
