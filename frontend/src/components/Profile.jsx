import React from "react";
import { Key, LogOut } from "lucide-react";

export function Profile({ user, onSignOut }) {
  const getRoleDetails = (role) => {
    switch (role) {
      case "ADMIN":
        return {
          title: "Admin",
          badgeBg: "#0f172a",
          badgeColor: "#f8fafc",
          description:
            "Manages external API integrations, user accounts, role assignments, security policies, system monitoring, and global execution logs.",
          permissions: [
            "Register, update, and remove external API integrations",
            "Create user accounts, assign roles, and manage account status",
            "Inspect system-wide execution logs and gateway health metrics",
            "Subject to sensitive-operation approval and Four-Eyes rules",
          ],
        };
      case "APPROVER":
        return {
          title: "Approver",
          badgeBg: "#065f46",
          badgeColor: "#ecfdf5",
          description:
            "Reviews pending sensitive operations, authorizes or rejects requests with recorded reasons, and audits relevant request records.",
          permissions: [
            "Inspect pending sensitive requests, parameters, and affected resources",
            "Approve or reject requests with permanently recorded rejection reasons",
            "Review historical approval and rejection decisions",
            "View approval-linked and failed request logs (cannot self-approve or register APIs)",
          ],
        };
      case "OPERATOR":
      default:
        return {
          title: "User",
          badgeBg: "#1d4ed8",
          badgeColor: "#eff6ff",
          description:
            "Submits natural-language requests, tracks approval status on own requests, and views personal request history.",
          permissions: [
            "Submit natural-language requests from the New Request page",
            "Track approval status and outcomes in My Requests",
            "Review completed and failed outcomes in Request History",
            "Strictly scoped to own requests and records",
          ],
        };
    }
  };

  const details = getRoleDetails(user?.role);

  return (
    <div style={{ maxWidth: 680, margin: "0 auto" }}>
      <div className="panel">
        <div className="panel-header">
          <div>
            <h2 className="panel-title">Account Profile</h2>
            <p className="panel-subtitle">Assigned role, permitted actions, and active session details</p>
          </div>
        </div>

        <div className="panel-body">
          <div style={{ display: "flex", alignItems: "center", gap: 16, marginBottom: 24 }}>
            <div
              style={{
                width: 52,
                height: 52,
                borderRadius: 6,
                backgroundColor: details.badgeBg,
                color: details.badgeColor,
                display: "flex",
                alignItems: "center",
                justifyContent: "center",
                fontWeight: 700,
                fontSize: 20,
              }}
            >
              {user?.username?.charAt(0).toUpperCase() || "U"}
            </div>
            <div>
              <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                <h3 style={{ fontSize: 18, fontWeight: 700, margin: 0 }}>{user?.username}</h3>
                <span
                  style={{
                    padding: "3px 8px",
                    borderRadius: 4,
                    backgroundColor: details.badgeBg,
                    color: details.badgeColor,
                    fontSize: 11,
                    fontWeight: 600,
                    textTransform: "uppercase",
                  }}
                >
                  {details.title}
                </span>
              </div>
              <p style={{ fontSize: 12, color: "var(--text-muted)", margin: "4px 0 0" }}>
                Account ID: <code style={{ fontFamily: "var(--font-mono)" }}>{user?.id}</code>
              </p>
            </div>
          </div>

          <div style={{ marginBottom: 20 }}>
            <h4 style={{ fontSize: 12, fontWeight: 600, marginBottom: 6, textTransform: "uppercase", color: "var(--text-muted)" }}>
              Role Responsibilities
            </h4>
            <p style={{ fontSize: 13, color: "var(--text-main)", lineHeight: 1.5 }}>
              {details.description}
            </p>
          </div>

          <div style={{ marginBottom: 24 }}>
            <h4 style={{ fontSize: 12, fontWeight: 600, marginBottom: 8, textTransform: "uppercase", color: "var(--text-muted)" }}>
              Authorized Capabilities
            </h4>
            <ul style={{ margin: 0, paddingLeft: 18, fontSize: 13, color: "var(--text-main)", display: "flex", flexDirection: "column", gap: 6 }}>
              {details.permissions.map((perm, idx) => (
                <li key={idx}>{perm}</li>
              ))}
            </ul>
          </div>

          <div style={{ padding: 14, borderRadius: 6, backgroundColor: "var(--bg-app)", border: "1px solid var(--border-subtle)", marginBottom: 20 }}>
            <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 6 }}>
              <Key size={14} color="var(--primary)" />
              <strong style={{ fontSize: 12 }}>Session Security</strong>
            </div>
            <p style={{ fontSize: 12, color: "var(--text-muted)", margin: 0 }}>
              Authentication tokens are held in memory only and never written to browser storage. Signing out immediately revokes your active token on the server.
            </p>
          </div>

          <div style={{ display: "flex", justifyContent: "flex-end" }}>
            <button className="btn btn-secondary" onClick={onSignOut}>
              <LogOut size={14} />
              <span>Sign Out</span>
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
