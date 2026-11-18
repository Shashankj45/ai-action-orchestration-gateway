import React, { useState, useEffect } from "react";
import { UserPlus, Check, AlertCircle, RefreshCw } from "lucide-react";
import { api } from "../services/api";

const ROLE_DISPLAY = {
  ADMIN: "Admin",
  APPROVER: "Approver",
  OPERATOR: "User",
};

export function UserManagement({ onUsersChanged, isDemo = false }) {
  const [users, setUsers] = useState([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [success, setSuccess] = useState(null);

  // Form State
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [role, setRole] = useState("OPERATOR");
  const [submitting, setSubmitting] = useState(false);

  const fetchUsers = async () => {
    setLoading(true);
    setError(null);
    try {
      const data = await api.listUsers();
      setUsers(data);
    } catch (err) {
      setError(err.message || "Failed to retrieve user accounts.");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchUsers();
  }, []);

  const handleCreateUser = async (e) => {
    e.preventDefault();
    if (!username.trim() || !password) return;

    setSubmitting(true);
    setError(null);
    setSuccess(null);

    try {
      await api.createUser({
        username: username.trim(),
        password,
        role,
      });
      setSuccess(
        `User '${username.trim()}' created with role ${ROLE_DISPLAY[role] || role}.`
      );
      setUsername("");
      setPassword("");
      setRole("OPERATOR");
      await fetchUsers();
      if (onUsersChanged) onUsersChanged();
    } catch (err) {
      setError(err.message || "User creation failed.");
    } finally {
      setSubmitting(false);
    }
  };

  const getRoleBadge = (userRole) => {
    switch (userRole) {
      case "ADMIN":
        return (
          <span style={{ padding: "3px 8px", borderRadius: 4, backgroundColor: "#0f172a", color: "#f8fafc", fontSize: 11, fontWeight: 600 }}>
            Admin
          </span>
        );
      case "APPROVER":
        return (
          <span style={{ padding: "3px 8px", borderRadius: 4, backgroundColor: "#065f46", color: "#ecfdf5", fontSize: 11, fontWeight: 600 }}>
            Approver
          </span>
        );
      case "OPERATOR":
      default:
        return (
          <span style={{ padding: "3px 8px", borderRadius: 4, backgroundColor: "#1d4ed8", color: "#eff6ff", fontSize: 11, fontWeight: 600 }}>
            User
          </span>
        );
    }
  };

  return (
    <div style={{ display: "grid", gridTemplateColumns: "1fr 1.6fr", gap: 20 }}>
      {/* Left Column: Create User Form */}
      <div className="panel">
        <div className="panel-header">
          <div>
            <h2 className="panel-title">Provision User Account</h2>
            <p className="panel-subtitle">Create accounts with explicit role assignments</p>
          </div>
        </div>

        <div className="panel-body">
          {isDemo && (
            <div className="alert-banner warning" style={{ marginBottom: 16 }}>
              <AlertCircle size={15} />
              <span>Demo Admin mode: user provisioning is disabled by the server. Showing isolated demo accounts only.</span>
            </div>
          )}

          {error && (
            <div className="alert-banner error" style={{ marginBottom: 16 }}>
              <AlertCircle size={15} />
              <span>{error}</span>
            </div>
          )}

          {success && (
            <div className="alert-banner success" style={{ marginBottom: 16 }}>
              <Check size={15} />
              <span>{success}</span>
            </div>
          )}

          <form onSubmit={handleCreateUser}>
            <div className="form-group">
              <label className="form-label">Username</label>
              <input
                type="text"
                required
                minLength={3}
                className="form-input"
                placeholder="e.g. jane.doe"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
              />
            </div>

            <div className="form-group">
              <label className="form-label">Initial Password</label>
              <input
                type="password"
                required
                minLength={8}
                className="form-input"
                placeholder="Minimum 8 characters"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
              />
            </div>

            <div className="form-group">
              <label className="form-label">Assigned Role</label>
              <select
                className="form-select"
                value={role}
                onChange={(e) => setRole(e.target.value)}
              >
                <option value="OPERATOR">User</option>
                <option value="APPROVER">Approver</option>
                <option value="ADMIN">Admin</option>
              </select>
              <p style={{ fontSize: 11, color: "var(--text-muted)", marginTop: 6 }}>
                {role === "OPERATOR" && "Submits natural-language requests and tracks own request status and history."}
                {role === "APPROVER" && "Reviews, approves, or rejects sensitive requests and views relevant logs."}
                {role === "ADMIN" && "Manages API integrations, users, roles, policies, monitoring, and system logs."}
              </p>
            </div>

            <div style={{ display: "flex", justifyContent: "flex-end", marginTop: 16 }}>
              <button
                type="submit"
                className="btn btn-primary"
                disabled={isDemo || submitting || !username.trim() || !password}
              >
                <UserPlus size={14} />
                <span>{isDemo ? "Disabled in Demo" : submitting ? "Creating..." : "Create Account"}</span>
              </button>
            </div>
          </form>
        </div>
      </div>

      {/* Right Column: User Accounts Table */}
      <div className="panel">
        <div className="panel-header">
          <div>
            <h2 className="panel-title">User Accounts ({users.length})</h2>
            <p className="panel-subtitle">Registered accounts, roles, and activation state</p>
          </div>
          <button className="btn btn-secondary btn-sm" onClick={fetchUsers} disabled={loading}>
            <RefreshCw size={13} />
            <span>Refresh</span>
          </button>
        </div>

        <div className="panel-body" style={{ padding: 0 }}>
          <div className="table-responsive">
            <table className="data-table">
              <thead>
                <tr>
                  <th>Username</th>
                  <th>Role</th>
                  <th>Status</th>
                  <th>Created At</th>
                </tr>
              </thead>
              <tbody>
                {users.map((u) => (
                  <tr key={u.id}>
                    <td>
                      <strong style={{ fontSize: 13 }}>{u.username}</strong>
                    </td>
                    <td>{getRoleBadge(u.role)}</td>
                    <td>
                      {u.is_active ? (
                        <span className="badge badge-safe">Active</span>
                      ) : (
                        <span className="badge badge-danger">Inactive</span>
                      )}
                    </td>
                    <td style={{ fontSize: 12, color: "var(--text-muted)" }}>
                      {new Date(u.created_at).toLocaleString()}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </div>
  );
}
