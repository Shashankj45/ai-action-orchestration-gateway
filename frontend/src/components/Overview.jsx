import React from "react";
import {
  Shield,
  Clock,
  CheckCircle2,
  Users,
  Server,
  FileText,
  AlertCircle,
  ArrowRight,
  UserCheck,
  Building2,
  KeyRound,
  ShieldAlert,
} from "lucide-react";

export function Overview({ user, apis, approvals, logs, users, onNavigate }) {
  const role = user?.role || "OPERATOR";

  // Operator metrics
  const myRequests = approvals.filter((a) => a.requested_by_user_id === user?.id);
  const myPending = myRequests.filter((a) => a.status === "PENDING");
  const myApproved = myRequests.filter((a) => a.status === "APPROVED");

  // Approver metrics
  const pendingCount = approvals.filter((a) => a.status === "PENDING").length;

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: "20px" }}>
      {/* Role Banner */}
      <div
        className="panel"
        style={{
          background: "linear-gradient(135deg, #0f172a 0%, #1e293b 100%)",
          color: "#ffffff",
          padding: "24px 28px",
          border: "1px solid #334155",
        }}
      >
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", flexWrap: "wrap", gap: "16px" }}>
          <div>
            <div style={{ display: "flex", alignItems: "center", gap: "10px", marginBottom: "8px" }}>
              <Building2 size={24} color="#38bdf8" />
              <h1 style={{ fontSize: "20px", fontWeight: "700", color: "#f8fafc", margin: 0 }}>
                Grand Hotel &amp; Resort — API Orchestration Gateway
              </h1>
            </div>
            <p style={{ fontSize: "14px", color: "#94a3b8", margin: 0, maxWidth: "680px" }}>
              {role === "ADMIN" &&
                "Hotel IT Administrator Console — Manage registered hotel APIs, user accounts, system monitoring, and global audit trails."}
              {role === "OPERATOR" &&
                `Welcome, ${user?.username} (Customer / Guest). Submit natural language requests for reservations, room modifications, and cancellations.`}
              {role === "APPROVER" &&
                `Hotel Duty Manager Console — Review, verify, and approve sensitive guest operations under strict Four-Eyes governance.`}
            </p>
          </div>

          <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
            <span
              style={{
                padding: "6px 12px",
                borderRadius: "6px",
                fontSize: "12px",
                fontWeight: "700",
                textTransform: "uppercase",
                letterSpacing: "0.05em",
                backgroundColor: role === "ADMIN" ? "#38bdf8" : role === "APPROVER" ? "#10b981" : "#818cf8",
                color: "#0f172a",
              }}
            >
              {role === "ADMIN" ? "Hotel IT Admin" : role === "APPROVER" ? "Hotel Manager" : "Customer / Requester"}
            </span>
          </div>
        </div>
      </div>

      {/* ADMIN KPI CARDS */}
      {role === "ADMIN" && (
        <>
          <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(220px, 1fr))", gap: "16px" }}>
            <div className="panel" style={{ padding: "20px" }}>
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                <span style={{ fontSize: "12px", fontWeight: "600", color: "var(--text-muted)", textTransform: "uppercase" }}>
                  Registered APIs
                </span>
                <Server size={18} color="var(--primary)" />
              </div>
              <div style={{ fontSize: "28px", fontWeight: "700", marginTop: "10px" }}>{apis.length}</div>
              <div style={{ fontSize: "12px", color: "var(--text-dim)", marginTop: "4px" }}>Active external hotel services</div>
            </div>

            <div className="panel" style={{ padding: "20px" }}>
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                <span style={{ fontSize: "12px", fontWeight: "600", color: "var(--text-muted)", textTransform: "uppercase" }}>
                  Active Users
                </span>
                <Users size={18} color="#0284c7" />
              </div>
              <div style={{ fontSize: "28px", fontWeight: "700", marginTop: "10px" }}>{users?.length || 3}</div>
              <div style={{ fontSize: "12px", color: "var(--text-dim)", marginTop: "4px" }}>Admins, Approvers, Operators</div>
            </div>

            <div className="panel" style={{ padding: "20px" }}>
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                <span style={{ fontSize: "12px", fontWeight: "600", color: "var(--text-muted)", textTransform: "uppercase" }}>
                  Pending Approvals
                </span>
                <Clock size={18} color="#f59e0b" />
              </div>
              <div style={{ fontSize: "28px", fontWeight: "700", marginTop: "10px", color: pendingCount > 0 ? "#d97706" : "inherit" }}>
                {pendingCount}
              </div>
              <div style={{ fontSize: "12px", color: "var(--text-dim)", marginTop: "4px" }}>Actions awaiting manager review</div>
            </div>

            <div className="panel" style={{ padding: "20px" }}>
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                <span style={{ fontSize: "12px", fontWeight: "600", color: "var(--text-muted)", textTransform: "uppercase" }}>
                  Total Executions
                </span>
                <FileText size={18} color="#10b981" />
              </div>
              <div style={{ fontSize: "28px", fontWeight: "700", marginTop: "10px" }}>{logs.length}</div>
              <div style={{ fontSize: "12px", color: "var(--text-dim)", marginTop: "4px" }}>Immutable audit records</div>
            </div>
          </div>

          {/* Quick Actions for Admin */}
          <div className="panel" style={{ padding: "20px" }}>
            <h3 style={{ fontSize: "15px", fontWeight: "600", marginBottom: "14px" }}>Hotel IT Administration Shortcuts</h3>
            <div style={{ display: "flex", flexWrap: "wrap", gap: "10px" }}>
              <button className="btn btn-secondary btn-sm" onClick={() => onNavigate("apis")}>
                <Server size={14} />
                <span>Configure APIs</span>
              </button>
              <button className="btn btn-secondary btn-sm" onClick={() => onNavigate("users")}>
                <Users size={14} />
                <span>Provision User Accounts</span>
              </button>
              <button className="btn btn-secondary btn-sm" onClick={() => onNavigate("logs")}>
                <FileText size={14} />
                <span>Inspect System Logs</span>
              </button>
              <button className="btn btn-secondary btn-sm" onClick={() => onNavigate("monitoring")}>
                <Shield size={14} />
                <span>System Monitoring &amp; Health</span>
              </button>
            </div>
          </div>
        </>
      )}

      {/* OPERATOR (CUSTOMER) KPI CARDS */}
      {role === "OPERATOR" && (
        <>
          <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(220px, 1fr))", gap: "16px" }}>
            <div className="panel" style={{ padding: "20px" }}>
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                <span style={{ fontSize: "12px", fontWeight: "600", color: "var(--text-muted)", textTransform: "uppercase" }}>
                  Pending Requests
                </span>
                <Clock size={18} color="#f59e0b" />
              </div>
              <div style={{ fontSize: "28px", fontWeight: "700", marginTop: "10px", color: myPending.length > 0 ? "#d97706" : "inherit" }}>
                {myPending.length}
              </div>
              <div style={{ fontSize: "12px", color: "var(--text-dim)", marginTop: "4px" }}>Awaiting Hotel Manager Review</div>
            </div>

            <div className="panel" style={{ padding: "20px" }}>
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                <span style={{ fontSize: "12px", fontWeight: "600", color: "var(--text-muted)", textTransform: "uppercase" }}>
                  Approved Actions
                </span>
                <CheckCircle2 size={18} color="#10b981" />
              </div>
              <div style={{ fontSize: "28px", fontWeight: "700", marginTop: "10px" }}>{myApproved.length}</div>
              <div style={{ fontSize: "12px", color: "var(--text-dim)", marginTop: "4px" }}>Successfully executed</div>
            </div>

            <div className="panel" style={{ padding: "20px" }}>
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                <span style={{ fontSize: "12px", fontWeight: "600", color: "var(--text-muted)", textTransform: "uppercase" }}>
                  Available Hotel Tools
                </span>
                <Server size={18} color="var(--primary)" />
              </div>
              <div style={{ fontSize: "28px", fontWeight: "700", marginTop: "10px" }}>{apis.length}</div>
              <div style={{ fontSize: "12px", color: "var(--text-dim)", marginTop: "4px" }}>External services ready to call</div>
            </div>

            <div className="panel" style={{ padding: "20px" }}>
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                <span style={{ fontSize: "12px", fontWeight: "600", color: "var(--text-muted)", textTransform: "uppercase" }}>
                  My Execution Records
                </span>
                <FileText size={18} color="#6366f1" />
              </div>
              <div style={{ fontSize: "28px", fontWeight: "700", marginTop: "10px" }}>{logs.length}</div>
              <div style={{ fontSize: "12px", color: "var(--text-dim)", marginTop: "4px" }}>Scoped to your account only</div>
            </div>
          </div>

          {/* Workflow Guide for Customer */}
          <div className="panel" style={{ padding: "24px" }}>
            <h3 style={{ fontSize: "16px", fontWeight: "600", marginBottom: "12px" }}>
              🏨 How Hotel Actions &amp; Guardrails Work
            </h3>
            <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(260px, 1fr))", gap: "16px" }}>
              <div style={{ padding: "16px", borderRadius: "8px", backgroundColor: "#f8fafc", border: "1px solid #e2e8f0" }}>
                <div style={{ display: "flex", alignItems: "center", gap: "8px", marginBottom: "6px" }}>
                  <CheckCircle2 size={16} color="#16a34a" />
                  <strong style={{ fontSize: "13px" }}>Safe Operations</strong>
                </div>
                <p style={{ fontSize: "12px", color: "#64748b", margin: 0 }}>
                  Queries such as viewing your reservation details or checking room availability execute automatically and return real-time data.
                </p>
              </div>

              <div style={{ padding: "16px", borderRadius: "8px", backgroundColor: "#fffbeb", border: "1px solid #fef3c7" }}>
                <div style={{ display: "flex", alignItems: "center", gap: "8px", marginBottom: "6px" }}>
                  <ShieldAlert size={16} color="#d97706" />
                  <strong style={{ fontSize: "13px", color: "#92400e" }}>Sensitive Operations</strong>
                </div>
                <p style={{ fontSize: "12px", color: "#78350f", margin: 0 }}>
                  Destructive actions such as <strong>cancelling booking 105</strong> or modifying reservations require explicit human approval from a Hotel Manager.
                </p>
              </div>
            </div>

            <div style={{ marginTop: "18px" }}>
              <button className="btn btn-primary" onClick={() => onNavigate("tasks")}>
                <span>Open AI Task Console</span>
                <ArrowRight size={14} />
              </button>
            </div>
          </div>
        </>
      )}

      {/* APPROVER (HOTEL MANAGER) KPI CARDS */}
      {role === "APPROVER" && (
        <>
          <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(240px, 1fr))", gap: "16px" }}>
            <div className="panel" style={{ padding: "20px", borderLeft: pendingCount > 0 ? "4px solid #f59e0b" : "1px solid var(--border)" }}>
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                <span style={{ fontSize: "12px", fontWeight: "600", color: "var(--text-muted)", textTransform: "uppercase" }}>
                  Pending Review Queue
                </span>
                <ShieldAlert size={18} color="#f59e0b" />
              </div>
              <div style={{ fontSize: "28px", fontWeight: "700", marginTop: "10px", color: pendingCount > 0 ? "#b45309" : "inherit" }}>
                {pendingCount}
              </div>
              <div style={{ fontSize: "12px", color: "var(--text-dim)", marginTop: "4px" }}>
                {pendingCount === 0 ? "All requests reviewed" : "Requests requiring supervisor decision"}
              </div>
            </div>

            <div className="panel" style={{ padding: "20px" }}>
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                <span style={{ fontSize: "12px", fontWeight: "600", color: "var(--text-muted)", textTransform: "uppercase" }}>
                  Four-Eyes Governance
                </span>
                <Shield size={18} color="#10b981" />
              </div>
              <div style={{ fontSize: "18px", fontWeight: "700", marginTop: "14px", color: "#047857" }}>
                Active &amp; Enforced
              </div>
              <div style={{ fontSize: "12px", color: "var(--text-dim)", marginTop: "4px" }}>
                Anti-Self-Approval prevents supervisors from approving own tasks
              </div>
            </div>

            <div className="panel" style={{ padding: "20px" }}>
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                <span style={{ fontSize: "12px", fontWeight: "600", color: "var(--text-muted)", textTransform: "uppercase" }}>
                  Relevant Audit Logs
                </span>
                <FileText size={18} color="#6366f1" />
              </div>
              <div style={{ fontSize: "28px", fontWeight: "700", marginTop: "10px" }}>{logs.length}</div>
              <div style={{ fontSize: "12px", color: "var(--text-dim)", marginTop: "4px" }}>Approved execution records</div>
            </div>
          </div>

          <div className="panel" style={{ padding: "20px" }}>
            <h3 style={{ fontSize: "15px", fontWeight: "600", marginBottom: "12px" }}>Manager Actions</h3>
            <div style={{ display: "flex", gap: "10px" }}>
              <button className="btn btn-primary" onClick={() => onNavigate("approvals")}>
                <Clock size={14} />
                <span>Review Pending Queue ({pendingCount})</span>
              </button>
              <button className="btn btn-secondary" onClick={() => onNavigate("approval_history")}>
                <FileText size={14} />
                <span>View Approval History</span>
              </button>
            </div>
          </div>
        </>
      )}
    </div>
  );
}
