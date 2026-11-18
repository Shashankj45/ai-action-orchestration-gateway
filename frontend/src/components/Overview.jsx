import React from "react";
import {
  Shield,
  Clock,
  CheckCircle2,
  XCircle,
  Users,
  Server,
  FileText,
  ArrowRight,
  ShieldAlert,
  Send,
  Sliders,
  Activity,
} from "lucide-react";

const ROLE_META = {
  ADMIN: {
    label: "Admin",
    title: "Gateway Administration Overview",
    subtitle:
      "Manage external API integrations, user accounts, role assignments, security policies, and system-wide audit logs.",
    badgeBg: "#0f172a",
    badgeColor: "#ffffff",
  },
  APPROVER: {
    label: "Approver",
    title: "Approval Review Overview",
    subtitle:
      "Inspect pending sensitive operations, authorize or reject requests with recorded reasons, and monitor relevant request logs.",
    badgeBg: "#065f46",
    badgeColor: "#ecfdf5",
  },
  OPERATOR: {
    label: "User",
    title: "Request Portal Overview",
    subtitle:
      "Submit natural-language requests, track pending approvals, and review completed request outcomes.",
    badgeBg: "#1d4ed8",
    badgeColor: "#eff6ff",
  },
};

export function Overview({ user, apis, approvals, logs, users, onNavigate }) {
  const role = user?.role || "OPERATOR";
  const meta = ROLE_META[role] || ROLE_META.OPERATOR;

  // User (OPERATOR) metrics
  const myPending = approvals.filter((a) => a.status === "PENDING");
  const myApproved = approvals.filter((a) => a.status === "APPROVED");
  const myRejected = approvals.filter((a) => a.status === "REJECTED");
  const myCompletedLogs = logs.filter((l) => l.status === "SUCCESS");

  // Approver / Admin metrics
  const pendingApprovalsCount = approvals.filter((a) => a.status === "PENDING").length;
  const failedLogsCount = logs.filter((l) => l.status === "FAILED").length;
  const activeUsersCount = users.filter((u) => u.is_active).length;

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 20 }}>
      {/* Clean Enterprise Role Summary Header */}
      <div className="panel" style={{ padding: "20px 24px" }}>
        <div
          style={{
            display: "flex",
            justifyContent: "space-between",
            alignItems: "flex-start",
            flexWrap: "wrap",
            gap: 16,
          }}
        >
          <div>
            <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 6 }}>
              <h1 style={{ fontSize: 18, fontWeight: 600, color: "var(--text-main)", margin: 0 }}>
                {meta.title}
              </h1>
              <span
                style={{
                  padding: "2px 8px",
                  borderRadius: 4,
                  fontSize: 11,
                  fontWeight: 600,
                  textTransform: "uppercase",
                  letterSpacing: "0.04em",
                  backgroundColor: meta.badgeBg,
                  color: meta.badgeColor,
                }}
              >
                {meta.label}
              </span>
            </div>
            <p style={{ fontSize: 13, color: "var(--text-muted)", margin: 0, maxWidth: 680 }}>
              {meta.subtitle}
            </p>
          </div>

          {role === "OPERATOR" && (
            <button className="btn btn-primary" onClick={() => onNavigate("new_request")}>
              <Send size={14} />
              <span>New Request</span>
            </button>
          )}
          {role === "APPROVER" && (
            <button className="btn btn-primary" onClick={() => onNavigate("approvals")}>
              <Clock size={14} />
              <span>Review Pending ({pendingApprovalsCount})</span>
            </button>
          )}
        </div>
      </div>

      {/* ================= USER OVERVIEW ================= */}
      {role === "OPERATOR" && (
        <>
          <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(210px, 1fr))", gap: 16 }}>
            <div className="panel" style={{ padding: 20 }}>
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                <span style={{ fontSize: 11, fontWeight: 600, color: "var(--text-muted)", textTransform: "uppercase" }}>
                  Pending Approval
                </span>
                <Clock size={17} color="#d97706" />
              </div>
              <div style={{ fontSize: 28, fontWeight: 700, marginTop: 10, color: myPending.length > 0 ? "#b45309" : "var(--text-main)" }}>
                {myPending.length}
              </div>
              <div style={{ fontSize: 12, color: "var(--text-dim)", marginTop: 4 }}>
                Requests awaiting review
              </div>
            </div>

            <div className="panel" style={{ padding: 20 }}>
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                <span style={{ fontSize: 11, fontWeight: 600, color: "var(--text-muted)", textTransform: "uppercase" }}>
                  Approved Requests
                </span>
                <CheckCircle2 size={17} color="#059669" />
              </div>
              <div style={{ fontSize: 28, fontWeight: 700, marginTop: 10 }}>{myApproved.length}</div>
              <div style={{ fontSize: 12, color: "var(--text-dim)", marginTop: 4 }}>
                Reviewed and authorized
              </div>
            </div>

            <div className="panel" style={{ padding: 20 }}>
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                <span style={{ fontSize: 11, fontWeight: 600, color: "var(--text-muted)", textTransform: "uppercase" }}>
                  Rejected Requests
                </span>
                <XCircle size={17} color="#dc2626" />
              </div>
              <div style={{ fontSize: 28, fontWeight: 700, marginTop: 10 }}>{myRejected.length}</div>
              <div style={{ fontSize: 12, color: "var(--text-dim)", marginTop: 4 }}>
                Declined with reviewer notes
              </div>
            </div>

            <div className="panel" style={{ padding: 20 }}>
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                <span style={{ fontSize: 11, fontWeight: 600, color: "var(--text-muted)", textTransform: "uppercase" }}>
                  Completed Outcomes
                </span>
                <FileText size={17} color="var(--primary)" />
              </div>
              <div style={{ fontSize: 28, fontWeight: 700, marginTop: 10 }}>{myCompletedLogs.length}</div>
              <div style={{ fontSize: 12, color: "var(--text-dim)", marginTop: 4 }}>
                Personal request history
              </div>
            </div>
          </div>

          <div className="panel" style={{ padding: 20 }}>
            <h2 style={{ fontSize: 15, fontWeight: 600, marginBottom: 14 }}>How Requests Are Processed</h2>
            <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(240px, 1fr))", gap: 16 }}>
              <div style={{ padding: 14, borderRadius: 6, backgroundColor: "var(--bg-app)", border: "1px solid var(--border-subtle)" }}>
                <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 6 }}>
                  <Send size={15} color="var(--primary)" />
                  <strong style={{ fontSize: 13 }}>1. Submit in Plain Language</strong>
                </div>
                <p style={{ fontSize: 12, color: "var(--text-muted)", margin: 0 }}>
                  Describe what you want to do on the New Request page. No technical parameters are required.
                </p>
              </div>

              <div style={{ padding: 14, borderRadius: 6, backgroundColor: "var(--bg-app)", border: "1px solid var(--border-subtle)" }}>
                <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 6 }}>
                  <ShieldAlert size={15} color="#d97706" />
                  <strong style={{ fontSize: 13 }}>2. Approval for Sensitive Changes</strong>
                </div>
                <p style={{ fontSize: 12, color: "var(--text-muted)", margin: 0 }}>
                  Read-only lookups finish immediately. Sensitive changes are reviewed by an approver before running.
                </p>
              </div>

              <div style={{ padding: 14, borderRadius: 6, backgroundColor: "var(--bg-app)", border: "1px solid var(--border-subtle)" }}>
                <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 6 }}>
                  <CheckCircle2 size={15} color="#059669" />
                  <strong style={{ fontSize: 13 }}>3. Track Status &amp; Outcomes</strong>
                </div>
                <p style={{ fontSize: 12, color: "var(--text-muted)", margin: 0 }}>
                  Check My Requests for pending reviews and Request History for completed results.
                </p>
              </div>
            </div>

            <div style={{ display: "flex", gap: 10, marginTop: 16 }}>
              <button className="btn btn-primary btn-sm" onClick={() => onNavigate("new_request")}>
                <span>Submit New Request</span>
                <ArrowRight size={13} />
              </button>
              <button className="btn btn-secondary btn-sm" onClick={() => onNavigate("my_requests")}>
                <span>View My Requests</span>
              </button>
              <button className="btn btn-secondary btn-sm" onClick={() => onNavigate("request_history")}>
                <span>View Request History</span>
              </button>
            </div>
          </div>
        </>
      )}

      {/* ================= APPROVER OVERVIEW ================= */}
      {role === "APPROVER" && (
        <>
          <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(230px, 1fr))", gap: 16 }}>
            <div
              className="panel"
              style={{
                padding: 20,
                borderLeft: pendingApprovalsCount > 0 ? "3px solid #d97706" : "1px solid var(--border-subtle)",
              }}
            >
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                <span style={{ fontSize: 11, fontWeight: 600, color: "var(--text-muted)", textTransform: "uppercase" }}>
                  Pending Approvals
                </span>
                <ShieldAlert size={17} color="#d97706" />
              </div>
              <div style={{ fontSize: 28, fontWeight: 700, marginTop: 10, color: pendingApprovalsCount > 0 ? "#b45309" : "var(--text-main)" }}>
                {pendingApprovalsCount}
              </div>
              <div style={{ fontSize: 12, color: "var(--text-dim)", marginTop: 4 }}>
                {pendingApprovalsCount === 0 ? "Queue is clear" : "Awaiting approver decision"}
              </div>
            </div>

            <div className="panel" style={{ padding: 20 }}>
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                <span style={{ fontSize: 11, fontWeight: 600, color: "var(--text-muted)", textTransform: "uppercase" }}>
                  Relevant Request Logs
                </span>
                <FileText size={17} color="var(--primary)" />
              </div>
              <div style={{ fontSize: 28, fontWeight: 700, marginTop: 10 }}>{logs.length}</div>
              <div style={{ fontSize: 12, color: "var(--text-dim)", marginTop: 4 }}>
                Approval-linked and failed records ({failedLogsCount} failed)
              </div>
            </div>

            <div className="panel" style={{ padding: 20 }}>
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                <span style={{ fontSize: 11, fontWeight: 600, color: "var(--text-muted)", textTransform: "uppercase" }}>
                  Four-Eyes Policy
                </span>
                <Shield size={17} color="#059669" />
              </div>
              <div style={{ fontSize: 18, fontWeight: 700, marginTop: 14, color: "#065f46" }}>
                Enforced
              </div>
              <div style={{ fontSize: 12, color: "var(--text-dim)", marginTop: 4 }}>
                Self-approval blocked; payloads frozen at submission
              </div>
            </div>
          </div>

          <div className="panel" style={{ padding: 20 }}>
            <h2 style={{ fontSize: 15, fontWeight: 600, marginBottom: 12 }}>Review Actions</h2>
            <div style={{ display: "flex", flexWrap: "wrap", gap: 10 }}>
              <button className="btn btn-primary btn-sm" onClick={() => onNavigate("approvals")}>
                <Clock size={13} />
                <span>Pending Approvals ({pendingApprovalsCount})</span>
              </button>
              <button className="btn btn-secondary btn-sm" onClick={() => onNavigate("approval_history")}>
                <FileText size={13} />
                <span>Approval History</span>
              </button>
              <button className="btn btn-secondary btn-sm" onClick={() => onNavigate("request_logs")}>
                <Activity size={13} />
                <span>Request Logs</span>
              </button>
            </div>
          </div>
        </>
      )}

      {/* ================= ADMIN OVERVIEW ================= */}
      {role === "ADMIN" && (
        <>
          <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(210px, 1fr))", gap: 16 }}>
            <div className="panel" style={{ padding: 20 }}>
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                <span style={{ fontSize: 11, fontWeight: 600, color: "var(--text-muted)", textTransform: "uppercase" }}>
                  Registered APIs
                </span>
                <Server size={17} color="var(--primary)" />
              </div>
              <div style={{ fontSize: 28, fontWeight: 700, marginTop: 10 }}>{apis.length}</div>
              <div style={{ fontSize: 12, color: "var(--text-dim)", marginTop: 4 }}>
                Configured integrations
              </div>
            </div>

            <div className="panel" style={{ padding: 20 }}>
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                <span style={{ fontSize: 11, fontWeight: 600, color: "var(--text-muted)", textTransform: "uppercase" }}>
                  User Accounts
                </span>
                <Users size={17} color="#0284c7" />
              </div>
              <div style={{ fontSize: 28, fontWeight: 700, marginTop: 10 }}>{users.length}</div>
              <div style={{ fontSize: 12, color: "var(--text-dim)", marginTop: 4 }}>
                {activeUsersCount} active across all roles
              </div>
            </div>

            <div className="panel" style={{ padding: 20 }}>
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                <span style={{ fontSize: 11, fontWeight: 600, color: "var(--text-muted)", textTransform: "uppercase" }}>
                  Pending Approvals
                </span>
                <Clock size={17} color="#d97706" />
              </div>
              <div style={{ fontSize: 28, fontWeight: 700, marginTop: 10, color: pendingApprovalsCount > 0 ? "#b45309" : "var(--text-main)" }}>
                {pendingApprovalsCount}
              </div>
              <div style={{ fontSize: 12, color: "var(--text-dim)", marginTop: 4 }}>
                Awaiting supervisor decision
              </div>
            </div>

            <div className="panel" style={{ padding: 20 }}>
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                <span style={{ fontSize: 11, fontWeight: 600, color: "var(--text-muted)", textTransform: "uppercase" }}>
                  Execution Logs
                </span>
                <FileText size={17} color="#059669" />
              </div>
              <div style={{ fontSize: 28, fontWeight: 700, marginTop: 10 }}>{logs.length}</div>
              <div style={{ fontSize: 12, color: "var(--text-dim)", marginTop: 4 }}>
                {failedLogsCount} failed recorded
              </div>
            </div>
          </div>

          <div className="panel" style={{ padding: 20 }}>
            <h2 style={{ fontSize: 15, fontWeight: 600, marginBottom: 14 }}>Administration Shortcuts</h2>
            <div style={{ display: "flex", flexWrap: "wrap", gap: 10 }}>
              <button className="btn btn-secondary btn-sm" onClick={() => onNavigate("apis")}>
                <Server size={13} />
                <span>API Registry</span>
              </button>
              <button className="btn btn-secondary btn-sm" onClick={() => onNavigate("users")}>
                <Users size={13} />
                <span>User Management</span>
              </button>
              <button className="btn btn-secondary btn-sm" onClick={() => onNavigate("roles")}>
                <Shield size={13} />
                <span>Role Management</span>
              </button>
              <button className="btn btn-secondary btn-sm" onClick={() => onNavigate("logs")}>
                <FileText size={13} />
                <span>Execution Logs</span>
              </button>
              <button className="btn btn-secondary btn-sm" onClick={() => onNavigate("security")}>
                <ShieldAlert size={13} />
                <span>Security &amp; Policies</span>
              </button>
              <button className="btn btn-secondary btn-sm" onClick={() => onNavigate("monitoring")}>
                <Activity size={13} />
                <span>System Monitoring</span>
              </button>
              <button className="btn btn-secondary btn-sm" onClick={() => onNavigate("settings")}>
                <Sliders size={13} />
                <span>Settings</span>
              </button>
            </div>
          </div>
        </>
      )}
    </div>
  );
}
