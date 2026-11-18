import React, { useState, useEffect } from "react";
import { Shield, RefreshCw, AlertCircle, Check, Save } from "lucide-react";
import { api } from "../services/api";

const ROLE_LABELS = {
  ADMIN: "Admin",
  APPROVER: "Approver",
  OPERATOR: "User",
};

export function RoleManagement({ currentUserId, onUpdated, isDemo = false }) {
  const [users, setUsers] = useState([]);
  const [drafts, setDrafts] = useState({});
  const [loading, setLoading] = useState(false);
  const [savingId, setSavingId] = useState(null);
  const [error, setError] = useState(null);
  const [success, setSuccess] = useState(null);

  const fetchUsers = async () => {
    setLoading(true);
    setError(null);
    try {
      const data = await api.listUsers();
      setUsers(data);
      const initialDrafts = {};
      data.forEach((u) => {
        initialDrafts[u.id] = { role: u.role, is_active: u.is_active };
      });
      setDrafts(initialDrafts);
    } catch (err) {
      setError(err.message || "Failed to load user accounts.");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchUsers();
  }, []);

  const activeAdminCount = users.filter((u) => u.role === "ADMIN" && u.is_active).length;

  const handleDraftChange = (userId, field, value) => {
    setDrafts((prev) => ({
      ...prev,
      [userId]: { ...prev[userId], [field]: value },
    }));
  };

  const hasChanges = (u) => {
    const d = drafts[u.id];
    if (!d) return false;
    return d.role !== u.role || d.is_active !== u.is_active;
  };

  const handleSave = async (u) => {
    const d = drafts[u.id];
    if (!d || !hasChanges(u)) return;

    setSavingId(u.id);
    setError(null);
    setSuccess(null);

    try {
      await api.updateUser(u.id, {
        role: d.role,
        is_active: d.is_active,
      });
      setSuccess(
        `Updated '${u.username}': Role set to ${ROLE_LABELS[d.role] || d.role}, status ${d.is_active ? "Active" : "Inactive"}.`
      );
      await fetchUsers();
      if (onUpdated) onUpdated();
    } catch (err) {
      setError(err.message || "Role update rejected by server.");
      // Revert draft for that user so UI reflects server truth
      setDrafts((prev) => ({
        ...prev,
        [u.id]: { role: u.role, is_active: u.is_active },
      }));
    } finally {
      setSavingId(null);
    }
  };

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 20 }}>
      {/* Governance Summary Bar */}
      <div className="panel" style={{ padding: "16px 20px" }}>
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", flexWrap: "wrap", gap: 12 }}>
          <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
            <Shield size={18} color="var(--primary)" />
            <div>
              <div style={{ fontSize: 14, fontWeight: 600 }}>Role &amp; Access Control Governance</div>
              <div style={{ fontSize: 12, color: "var(--text-muted)" }}>
                Role changes and account deactivations take effect immediately on the next API request. At least one active Admin must remain at all times.
              </div>
            </div>
          </div>
          <div
            style={{
              padding: "6px 12px",
              borderRadius: 4,
              backgroundColor: "var(--bg-subtle)",
              border: "1px solid var(--border-subtle)",
              fontSize: 12,
              fontWeight: 600,
            }}
          >
            Active Admins: {activeAdminCount}
          </div>
        </div>
      </div>

      {/* Role Assignment Table */}
      <div className="panel">
        <div className="panel-header">
          <div>
            <h2 className="panel-title">Role Management ({users.length})</h2>
            <p className="panel-subtitle">
              Assign roles (User, Approver, Admin) and manage account status with last-admin protection
            </p>
          </div>
          <button className="btn btn-secondary btn-sm" onClick={fetchUsers} disabled={loading}>
            <RefreshCw size={13} />
            <span>Refresh</span>
          </button>
        </div>

        <div className="panel-body" style={{ padding: 0 }}>
          {isDemo && (
            <div style={{ padding: "16px 20px 0" }}>
              <div className="alert-banner warning">
                <AlertCircle size={15} />
                <span>Demo Admin mode: role and account status changes are disabled by the server. Showing isolated demo accounts only.</span>
              </div>
            </div>
          )}

          {error && (
            <div style={{ padding: "16px 20px 0" }}>
              <div className="alert-banner error">
                <AlertCircle size={15} />
                <span>{error}</span>
              </div>
            </div>
          )}

          {success && (
            <div style={{ padding: "16px 20px 0" }}>
              <div className="alert-banner success">
                <Check size={15} />
                <span>{success}</span>
              </div>
            </div>
          )}

          <div className="table-responsive">
            <table className="data-table">
              <thead>
                <tr>
                  <th>Account</th>
                  <th>Assigned Role</th>
                  <th>Account Status</th>
                  <th>Created</th>
                  <th style={{ textAlign: "right" }}>Action</th>
                </tr>
              </thead>
              <tbody>
                {users.map((u) => {
                  const draft = drafts[u.id] || { role: u.role, is_active: u.is_active };
                  const isSoleAdmin = u.role === "ADMIN" && u.is_active && activeAdminCount <= 1;
                  const dirty = hasChanges(u);

                  return (
                    <tr key={u.id}>
                      <td>
                        <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                          <strong style={{ fontSize: 13 }}>{u.username}</strong>
                          {u.id === currentUserId && (
                            <span
                              style={{
                                fontSize: 10,
                                fontWeight: 600,
                                padding: "2px 6px",
                                borderRadius: 4,
                                backgroundColor: "var(--bg-subtle)",
                                color: "var(--text-muted)",
                              }}
                            >
                              YOU
                            </span>
                          )}
                          {isSoleAdmin && (
                            <span
                              style={{
                                fontSize: 10,
                                fontWeight: 600,
                                padding: "2px 6px",
                                borderRadius: 4,
                                backgroundColor: "#fef3c7",
                                color: "#92400e",
                              }}
                              title="Cannot be demoted or deactivated while it is the only active Admin account"
                            >
                              LAST ADMIN
                            </span>
                          )}
                        </div>
                      </td>

                      <td>
                        <select
                          className="form-select"
                          style={{ width: 160, padding: "5px 8px", fontSize: 12 }}
                          value={draft.role}
                          onChange={(e) => handleDraftChange(u.id, "role", e.target.value)}
                          disabled={isDemo || savingId === u.id}
                        >
                          <option value="OPERATOR">User</option>
                          <option value="APPROVER">Approver</option>
                          <option value="ADMIN">Admin</option>
                        </select>
                      </td>

                      <td>
                        <select
                          className="form-select"
                          style={{ width: 130, padding: "5px 8px", fontSize: 12 }}
                          value={draft.is_active ? "active" : "inactive"}
                          onChange={(e) =>
                            handleDraftChange(u.id, "is_active", e.target.value === "active")
                          }
                          disabled={isDemo || savingId === u.id}
                        >
                          <option value="active">Active</option>
                          <option value="inactive">Inactive</option>
                        </select>
                      </td>

                      <td style={{ fontSize: 12, color: "var(--text-dim)" }}>
                        {new Date(u.created_at).toLocaleDateString()}
                      </td>

                      <td style={{ textAlign: "right" }}>
                        <button
                          className={`btn btn-sm ${dirty && !isDemo ? "btn-primary" : "btn-secondary"}`}
                          disabled={isDemo || !dirty || savingId === u.id}
                          onClick={() => handleSave(u)}
                        >
                          <Save size={12} />
                          <span>{isDemo ? "Read-Only" : savingId === u.id ? "Saving..." : "Save"}</span>
                        </button>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </div>
      </div>

      {/* Role Permissions Reference Matrix */}
      <div className="panel">
        <div className="panel-header">
          <div>
            <h3 className="panel-title">Enforced Role Permissions Matrix</h3>
            <p className="panel-subtitle">Server-side authorization boundaries enforced on every API route</p>
          </div>
        </div>
        <div className="panel-body" style={{ padding: 0 }}>
          <div className="table-responsive">
            <table className="data-table">
              <thead>
                <tr>
                  <th>Capability</th>
                  <th>User</th>
                  <th>Approver</th>
                  <th>Admin</th>
                </tr>
              </thead>
              <tbody>
                <tr>
                  <td>Submit natural-language requests</td>
                  <td>Allowed</td>
                  <td>Blocked (403)</td>
                  <td>Allowed (No sensitive bypass)</td>
                </tr>
                <tr>
                  <td>View own requests &amp; sanitized history</td>
                  <td>Allowed (Own only)</td>
                  <td>N/A</td>
                  <td>Allowed</td>
                </tr>
                <tr>
                  <td>Inspect &amp; decide pending approvals</td>
                  <td>Blocked (403)</td>
                  <td>Allowed (No self-approval)</td>
                  <td>Allowed (No self-approval)</td>
                </tr>
                <tr>
                  <td>View approval-linked &amp; failed logs</td>
                  <td>Blocked</td>
                  <td>Allowed (Scoped)</td>
                  <td>Allowed (System-wide)</td>
                </tr>
                <tr>
                  <td>Manage API Registry &amp; Credentials</td>
                  <td>Blocked (403)</td>
                  <td>Read-only metadata</td>
                  <td>Full management</td>
                </tr>
                <tr>
                  <td>Manage Users, Roles &amp; System Telemetry</td>
                  <td>Blocked (403)</td>
                  <td>Blocked (403)</td>
                  <td>Allowed</td>
                </tr>
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </div>
  );
}
