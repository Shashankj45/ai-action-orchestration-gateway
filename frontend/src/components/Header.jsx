import React, { useEffect, useState } from "react";
import { Shield, RefreshCw, LogOut, UserCheck, ArrowLeftRight } from "lucide-react";
import { api } from "../services/api";
import { ROLE_DISPLAY, DEMO_ROLE_OPTIONS, getTabsForRole } from "../utils/rbac";

export function Header({
  activeTab,
  setActiveTab,
  pendingCount,
  onRefresh,
  user,
  onSignOut,
  onSwitchDemoRole,
  switchingRole,
}) {
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

  const visibleTabs = user ? getTabsForRole(user.role, pendingCount) : [];

  const getRoleBadgeStyle = (role) => {
    switch (role) {
      case "ADMIN":
        return { backgroundColor: "#0f172a", color: "#ffffff" };
      case "APPROVER":
        return { backgroundColor: "#065f46", color: "#ecfdf5" };
      case "OPERATOR":
      default:
        return { backgroundColor: "#1d4ed8", color: "#eff6ff" };
    }
  };

  const currentRoleLabel = ROLE_DISPLAY[user?.role] || "User";

  return (
    <header>
      <div className="topbar">
        <div className="brand">
          <Shield size={18} strokeWidth={2.5} color="#0f172a" />
          <span className="brand-title">AI Action Gateway</span>
          {user?.role === "ADMIN" && <span className="brand-badge">ADMIN CONSOLE</span>}
          {user?.role === "APPROVER" && <span className="brand-badge">APPROVER PORTAL</span>}
          {user?.role === "OPERATOR" && <span className="brand-badge">REQUEST PORTAL</span>}
        </div>

        <div className="header-meta">
          <div className="health-indicator">
            <span className={`status-dot ${healthy ? "" : "error"}`}></span>
            <span>{healthy ? "Online" : "Offline"}</span>
          </div>

          {user && (
            <>
              <span>|</span>
              <div style={{ display: "flex", alignItems: "center", gap: "0.375rem" }}>
                <UserCheck size={14} color="#64748b" />
                <span style={{ fontWeight: "600", color: "#0f172a", fontSize: "0.8125rem" }}>
                  {user.username}
                </span>
                <span
                  style={{
                    padding: "0.125rem 0.5rem",
                    borderRadius: "4px",
                    fontSize: "0.6875rem",
                    fontWeight: "600",
                    textTransform: "uppercase",
                    letterSpacing: "0.04em",
                    ...getRoleBadgeStyle(user.role),
                  }}
                >
                  {user.is_demo ? `Demo ${currentRoleLabel}` : currentRoleLabel}
                </span>
              </div>
              <button
                className="btn btn-secondary btn-sm"
                onClick={onSignOut}
                title="Sign out and revoke session token"
                style={{ marginLeft: 4 }}
              >
                <LogOut size={12} />
                <span>{user.is_demo ? "Exit Demo" : "Sign Out"}</span>
              </button>
            </>
          )}

          {user && (
            <button
              className="btn btn-secondary btn-sm"
              onClick={onRefresh}
              title="Refresh active view"
            >
              <RefreshCw size={13} />
              <span>Sync</span>
            </button>
          )}
        </div>
      </div>

      {/* Recruiter Demo Environment Banner */}
      {user?.is_demo && (
        <div
          style={{
            backgroundColor: "#fffbeb",
            borderBottom: "1px solid #fde68a",
            padding: "8px 32px",
            display: "flex",
            alignItems: "center",
            justifyContent: "space-between",
            flexWrap: "wrap",
            gap: "10px",
            fontSize: "12px",
            color: "#78350f",
          }}
        >
          <div style={{ display: "flex", alignItems: "center", gap: "10px", flexWrap: "wrap" }}>
            <span
              style={{
                fontWeight: 700,
                textTransform: "uppercase",
                letterSpacing: "0.04em",
                fontSize: "11px",
                padding: "2px 7px",
                borderRadius: "4px",
                backgroundColor: "#92400e",
                color: "#ffffff",
              }}
            >
              Recruiter Demo Environment
            </span>
            <span>
              Exploring as <strong>{currentRoleLabel}</strong>
              {user.role === "ADMIN" ? " (Read-Only)" : ""}. Isolated sandbox with fictional data — no real external APIs or production records.
            </span>
          </div>

          <div style={{ display: "flex", alignItems: "center", gap: "6px", flexWrap: "wrap" }}>
            <ArrowLeftRight size={13} color="#92400e" />
            <span style={{ fontWeight: 600, fontSize: "11px", color: "#92400e" }}>Switch role:</span>
            {DEMO_ROLE_OPTIONS.map((opt) => {
              const isCurrent = opt.backendRole === user.role;
              return (
                <button
                  key={opt.key}
                  type="button"
                  disabled={isCurrent || Boolean(switchingRole)}
                  onClick={() => onSwitchDemoRole && onSwitchDemoRole(opt.key)}
                  className="btn btn-secondary btn-sm"
                  style={{
                    padding: "3px 8px",
                    fontSize: "11px",
                    backgroundColor: isCurrent ? "#92400e" : "#ffffff",
                    color: isCurrent ? "#ffffff" : "#0f172a",
                    borderColor: isCurrent ? "#92400e" : "#d97706",
                    opacity: switchingRole && !isCurrent ? 0.6 : 1,
                  }}
                >
                  {switchingRole === opt.key ? "Switching..." : opt.shortLabel}
                </button>
              );
            })}
            <button
              type="button"
              onClick={onSignOut}
              className="btn btn-secondary btn-sm"
              style={{ padding: "3px 8px", fontSize: "11px" }}
            >
              Return to Login
            </button>
          </div>
        </div>
      )}

      {visibleTabs.length > 0 && (
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
      )}
    </header>
  );
}
