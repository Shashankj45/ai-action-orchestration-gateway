import React, { useEffect, useState } from "react";
import { Shield, RefreshCw, LogOut, UserCheck } from "lucide-react";
import { api } from "../services/api";

export function Header({ activeTab, setActiveTab, pendingCount, onRefresh, user, onSignOut }) {
  const [healthy, setHealthy] = useState(true);

  useEffect(() => {
    const check = async () => {
      try {
        await api.checkHealth();
        setHealthy(true);
      } catch {
        setHealthy(false);
      }
    };
    check();
    const interval = setInterval(check, 10000);
    return () => clearInterval(interval);
  }, []);

  const allTabs = [
    { id: "tasks", label: "Task Console", roles: ["OPERATOR", "ADMIN"] },
    { id: "apis", label: "API Registry", roles: ["OPERATOR", "APPROVER", "ADMIN"] },
    { id: "approvals", label: "Approval Queue", count: pendingCount, alert: pendingCount > 0, roles: ["APPROVER", "ADMIN"] },
    { id: "logs", label: "Audit Logs & Replay", roles: ["APPROVER", "ADMIN"] },
  ];

  const visibleTabs = allTabs.filter(
    (tab) => !user || !tab.roles || tab.roles.includes(user.role)
  );

  const getRoleBadgeStyle = (role) => {
    switch (role) {
      case "ADMIN":
        return { backgroundColor: "#1e293b", color: "#ffffff" };
      case "APPROVER":
        return { backgroundColor: "#065f46", color: "#ecfdf5" };
      case "OPERATOR":
      default:
        return { backgroundColor: "#1e40af", color: "#eff6ff" };
    }
  };

  return (
    <header>
      <div className="topbar">
        <div className="brand">
          <Shield size={18} strokeWidth={2.5} color="#0f172a" />
          <span className="brand-title">AI Action Gateway</span>
          <span className="brand-badge">ZERO-TRUST RBAC</span>
        </div>

        <div className="header-meta">
          <div className="health-indicator">
            <span className={`status-dot ${healthy ? "" : "error"}`}></span>
            <span>{healthy ? "Gateway Online" : "Service Disconnected"}</span>
          </div>
          <span>•</span>
          <span>Environment: <strong style={{ color: "var(--text-main)" }}>Sandbox</strong></span>

          {user && (
            <>
              <span>•</span>
              <div style={{ display: "flex", alignItems: "center", gap: "0.375rem" }}>
                <UserCheck size={14} color="#64748b" />
                <span style={{ fontWeight: "600", color: "#1e293b", fontSize: "0.8125rem" }}>{user.username}</span>
                <span style={{
                  padding: "0.125rem 0.375rem",
                  borderRadius: "4px",
                  fontSize: "0.6875rem",
                  fontWeight: "600",
                  textTransform: "uppercase",
                  letterSpacing: "0.04em",
                  ...getRoleBadgeStyle(user.role),
                }}>
                  {user.role}
                </span>
              </div>
              <button
                className="btn btn-secondary btn-sm"
                onClick={onSignOut}
                title="Sign out (clears in-memory token)"
                style={{ marginLeft: 6, display: "flex", alignItems: "center", gap: "4px" }}
              >
                <LogOut size={12} />
                <span>Sign Out</span>
              </button>
            </>
          )}

          <button
            className="btn btn-secondary btn-sm"
            onClick={onRefresh}
            title="Refresh active view"
            style={{ marginLeft: 6 }}
          >
            <RefreshCw size={13} />
            <span>Sync</span>
          </button>
        </div>
      </div>

      <nav className="tabs-nav">
        {visibleTabs.map((tab) => (
          <button
            key={tab.id}
            className={`tab-btn ${activeTab === tab.id ? "active" : ""}`}
            onClick={() => setActiveTab(tab.id)}
          >
            <span>{tab.label}</span>
            {tab.count !== undefined && (
              <span className={`tab-count ${tab.alert ? "alert" : ""}`}>
                {tab.count}
              </span>
            )}
          </button>
        ))}
      </nav>
    </header>
  );
}
