import React, { useState, useEffect } from "react";
import { Clock, CheckCircle2, XCircle, AlertCircle, RefreshCw, ShieldAlert, ArrowRight } from "lucide-react";
import { api } from "../services/api";

export function MyRequests({ onSwitchToConsole }) {
  const [requests, setRequests] = useState([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  const fetchMyRequests = async () => {
    setLoading(true);
    setError(null);
    try {
      const data = await api.listMyRequests();
      setRequests(data);
    } catch (err) {
      setError(err.message || "Failed to retrieve your submitted requests.");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchMyRequests();
    const interval = setInterval(fetchMyRequests, 10000);
    return () => clearInterval(interval);
  }, []);

  const getStatusBadge = (status) => {
    switch (status) {
      case "PENDING":
        return (
          <span style={{ display: "inline-flex", alignItems: "center", gap: "4px", padding: "3px 8px", borderRadius: "4px", backgroundColor: "#fef3c7", color: "#92400e", fontSize: "11px", fontWeight: "700" }}>
            <Clock size={12} />
            <span>Awaiting Hotel Manager Review</span>
          </span>
        );
      case "APPROVED":
        return (
          <span style={{ display: "inline-flex", alignItems: "center", gap: "4px", padding: "3px 8px", borderRadius: "4px", backgroundColor: "#dcfce7", color: "#166534", fontSize: "11px", fontWeight: "700" }}>
            <CheckCircle2 size={12} />
            <span>Approved &amp; Executed</span>
          </span>
        );
      case "REJECTED":
        return (
          <span style={{ display: "inline-flex", alignItems: "center", gap: "4px", padding: "3px 8px", borderRadius: "4px", backgroundColor: "#fee2e2", color: "#991b1b", fontSize: "11px", fontWeight: "700" }}>
            <XCircle size={12} />
            <span>Rejected by Manager</span>
          </span>
        );
      default:
        return <span className="badge">{status}</span>;
    }
  };

  return (
    <div className="panel">
      <div className="panel-header">
        <div>
          <h2 className="panel-title">My Submitted Requests &amp; Approval Status</h2>
          <p className="panel-subtitle">Track your sensitive booking operations awaiting hotel supervisor verification</p>
        </div>
        <button className="btn btn-secondary btn-sm" onClick={fetchMyRequests} disabled={loading}>
          <RefreshCw size={13} className={loading ? "animate-spin" : ""} />
          <span>Refresh</span>
        </button>
      </div>

      <div className="panel-body" style={{ padding: 0 }}>
        {error && (
          <div style={{ padding: "16px 20px" }}>
            <div className="alert-banner error">
              <AlertCircle size={15} />
              <span>{error}</span>
            </div>
          </div>
        )}

        {requests.length === 0 && !loading && (
          <div style={{ padding: "48px 20px", textAlign: "center", color: "var(--text-muted)" }}>
            <Clock size={32} style={{ margin: "0 auto 12px", opacity: 0.5 }} />
            <p style={{ fontSize: "14px", fontWeight: "600", color: "var(--text-main)" }}>No Requests Submitted Yet</p>
            <p style={{ fontSize: "12px", maxWidth: "420px", margin: "4px auto 16px" }}>
              When you request a sensitive action (e.g. <em>"Cancel my booking 105"</em>), it will appear here with live manager review status.
            </p>
            {onSwitchToConsole && (
              <button className="btn btn-primary btn-sm" onClick={onSwitchToConsole}>
                <span>Go to AI Task Console</span>
                <ArrowRight size={13} />
              </button>
            )}
          </div>
        )}

        {requests.length > 0 && (
          <div className="table-responsive">
            <table className="data-table">
              <thead>
                <tr>
                  <th>Target Action</th>
                  <th>Status</th>
                  <th>Classification Reason</th>
                  <th>Submitted At</th>
                  <th>Manager Decision At</th>
                </tr>
              </thead>
              <tbody>
                {requests.map((r) => (
                  <tr key={r.id}>
                    <td>
                      <div style={{ display: "flex", alignItems: "center", gap: "6px" }}>
                        <span className={`method-badge method-${r.http_method.toLowerCase()}`}>
                          {r.http_method}
                        </span>
                        <code style={{ fontSize: "12px", fontWeight: "600" }}>{r.endpoint_path}</code>
                      </div>
                    </td>
                    <td>{getStatusBadge(r.status)}</td>
                    <td style={{ fontSize: "12px", color: "var(--text-muted)", maxWidth: "280px" }}>
                      {r.classification_reason}
                    </td>
                    <td style={{ fontSize: "12px", color: "var(--text-dim)" }}>
                      {new Date(r.created_at).toLocaleString()}
                    </td>
                    <td style={{ fontSize: "12px", color: "var(--text-dim)" }}>
                      {r.decided_at ? new Date(r.decided_at).toLocaleString() : "—"}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}
