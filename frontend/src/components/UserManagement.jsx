import React, { useState, useEffect } from "react";
import { UserPlus, Users, Shield, Check, AlertCircle, RefreshCw } from "lucide-react";
import { api } from "../services/api";

export function UserManagement() {
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
      setSuccess(`User '${username.trim()}' successfully provisioned as ${role}.`);
      setUsername("");
      setPassword("");
      setRole("OPERATOR");
      fetchUsers();
    } catch (err) {
      setError(err.message || "User creation failed.");
    } finally {
      setSubmitting(false);
    }
  };

  const getRoleBadge = (userRole) => {
    switch (userRole) {
      case "ADMIN":
        return <span style={{ padding: "3px 8px", borderRadius: "4px", backgroundColor: "#0f172a", color: "#f8fafc", fontSize: "11px", fontWeight: "700" }}>ADMIN</span>;
      case "APPROVER":
        return <span style={{ padding: "3px 8px", borderRadius: "4px", backgroundColor: "#047857", color: "#ecfdf5", fontSize: "11px", fontWeight: "700" }}>HOTEL MANAGER (APPROVER)</span>;
      case "OPERATOR":
      default:
        return <span style={{ padding: "3px 8px", borderRadius: "4px", backgroundColor: "#1d4ed8", color: "#eff6ff", fontSize: "11px", fontWeight: "700" }}>CUSTOMER (OPERATOR)</span>;
    }
  };

  return (
    <div style={{ display: "grid", gridTemplateColumns: "1fr 1.6fr", gap: "20px" }}>
      {/* Left Column: Create User Form */}
      <div className="panel">
        <div className="panel-header">
          <div>
            <h2 className="panel-title">Provision User Account</h2>
            <p className="panel-subtitle">Create accounts with explicit role assignments</p>
          </div>
        </div>

        <div className="panel-body">
          {error && (
            <div className="alert-banner error" style={{ marginBottom: "16px" }}>
              <AlertCircle size={15} />
              <span>{error}</span>
            </div>
          )}

          {success && (
            <div className="alert-banner success" style={{ marginBottom: "16px" }}>
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
                className="form-input"
                placeholder="e.g. manager_jane or guest_105"
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
                <option value="OPERATOR">Customer / Requester (OPERATOR)</option>
                <option value="APPROVER">Hotel Manager (APPROVER)</option>
                <option value="ADMIN">Hotel IT Administrator (ADMIN)</option>
              </select>
              <p style={{ fontSize: "11px", color: "var(--text-dim)", marginTop: "6px" }}>
                {role === "OPERATOR" && "Permitted to submit tasks and view own requests. Cannot register APIs or approve actions."}
                {role === "APPROVER" && "Permitted to review and decide pending sensitive requests. Cannot execute tasks."}
                {role === "ADMIN" && "Full administrative control over gateway, users, APIs, and security configurations."}
              </p>
            </div>

            <div style={{ display: "flex", justifyContent: "flex-end", marginTop: "16px" }}>
              <button
                type="submit"
                className="btn btn-primary"
                disabled={submitting || !username.trim() || !password}
              >
                <UserPlus size={14} />
                <span>{submitting ? "Provisioning..." : "Create User Account"}</span>
              </button>
            </div>
          </form>
        </div>
      </div>

      {/* Right Column: User Accounts Table */}
      <div className="panel">
        <div className="panel-header">
          <div>
            <h2 className="panel-title">Registered Accounts ({users.length})</h2>
            <p className="panel-subtitle">Current database users and authorization roles</p>
          </div>
          <button className="btn btn-secondary btn-sm" onClick={fetchUsers} disabled={loading}>
            <RefreshCw size={13} className={loading ? "animate-spin" : ""} />
            <span>Sync</span>
          </button>
        </div>

        <div className="panel-body" style={{ padding: 0 }}>
          <div className="table-responsive">
            <table className="data-table">
              <thead>
                <tr>
                  <th>Username</th>
                  <th>Assigned Role</th>
                  <th>Status</th>
                  <th>Created At</th>
                </tr>
              </thead>
              <tbody>
                {users.map((u) => (
                  <tr key={u.id}>
                    <td>
                      <strong style={{ fontSize: "13px" }}>{u.username}</strong>
                    </td>
                    <td>{getRoleBadge(u.role)}</td>
                    <td>
                      <span className="badge badge-success">Active</span>
                    </td>
                    <td style={{ fontSize: "12px", color: "var(--text-dim)" }}>
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
