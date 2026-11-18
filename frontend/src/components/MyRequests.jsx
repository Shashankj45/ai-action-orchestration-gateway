import React, { useState, useEffect } from "react";
import { Clock, CheckCircle2, XCircle, AlertCircle, RefreshCw, ArrowRight } from "lucide-react";
import { api } from "../services/api";

export function MyRequests({ onNewRequest }) {
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
      setError(err.message || "Failed to retrieve your requests.");
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
          <span className="badge badge-sensitive">
            <Clock size={11} />
            <span>Awaiting Review</span>
          </span>
        );
      case "APPROVED":
        return (
          <span className="badge badge-safe">
            <CheckCircle2 size={11} />
            <span>Approved</span>
          </span>
        );
      case "REJECTED":
        return (
          <span className="badge badge-danger">
            <XCircle size={11} />
            <span>Rejected</span>
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
          <h2 className="panel-title">My Requests</h2>
          <p className="panel-subtitle">
            Track requests awaiting approval and review outcomes on your submissions
          </p>
        </div>
        <div style={{ display: "flex", gap: 8 }}>
          {onNewRequest && (
            <button className="btn btn-primary btn-sm" onClick={onNewRequest}>
              <span>New Request</span>
              <ArrowRight size={13} />
            </button>
          )}
          <button className="btn btn-secondary btn-sm" onClick={fetchMyRequests} disabled={loading}>
            <RefreshCw size={13} />
            <span>Refresh</span>
          </button>
        </div>
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
            <p style={{ fontSize: 14, fontWeight: 600, color: "var(--text-main)" }}>
              No Pending or Reviewed Requests
            </p>
            <p style={{ fontSize: 12, maxWidth: 420, margin: "4px auto 16px" }}>
              When you submit a request that requires approval, its live progress and decision outcome will appear here.
            </p>
            {onNewRequest && (
              <button className="btn btn-primary btn-sm" onClick={onNewRequest}>
                <span>Submit New Request</span>
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
                  <th>Reference</th>
                  <th>Service</th>
                  <th>Status</th>
                  <th>Submitted</th>
                  <th>Decision Date</th>
                  <th>Outcome Notes</th>
                </tr>
              </thead>
              <tbody>
                {requests.map((r) => (
                  <tr key={r.id}>
                    <td>
                      <code style={{ fontFamily: "var(--font-mono)", fontSize: 12 }}>
                        {r.id.slice(0, 8)}
                      </code>
                    </td>
                    <td style={{ fontWeight: 500, fontSize: 13 }}>
                      {r.api_name || r.summary || "Requested Action"}
                    </td>
                    <td>{getStatusBadge(r.status)}</td>
                    <td style={{ fontSize: 12, color: "var(--text-muted)" }}>
                      {new Date(r.created_at).toLocaleString()}
                    </td>
                    <td style={{ fontSize: 12, color: "var(--text-muted)" }}>
                      {r.decided_at ? new Date(r.decided_at).toLocaleString() : "—"}
                    </td>
                    <td style={{ fontSize: 12, color: "var(--text-muted)", maxWidth: 280 }}>
                      {r.status === "PENDING" && "Waiting for an authorized approver to review."}
                      {r.status === "APPROVED" &&
                        `Approved${r.decided_by_username ? ` by ${r.decided_by_username}` : ""} and completed.`}
                      {r.status === "REJECTED" && (
                        <span style={{ color: "var(--danger-text)" }}>
                          {r.rejection_reason
                            ? `Reason: ${r.rejection_reason}`
                            : "Request was declined by an approver."}
                        </span>
                      )}
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
