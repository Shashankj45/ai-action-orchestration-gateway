import React, { useState, useEffect } from "react";
import { CheckCircle2, XCircle, RefreshCw, FileText, AlertCircle } from "lucide-react";
import { api } from "../services/api";

export function ApprovalHistory() {
  const [history, setHistory] = useState([]);
  const [filter, setFilter] = useState("ALL");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  const fetchHistory = async () => {
    setLoading(true);
    setError(null);
    try {
      const [approvedList, rejectedList] = await Promise.all([
        api.listApprovals({ status: "APPROVED" }).catch(() => []),
        api.listApprovals({ status: "REJECTED" }).catch(() => []),
      ]);
      const combined = [...approvedList, ...rejectedList].sort(
        (a, b) => new Date(b.decided_at || b.created_at) - new Date(a.decided_at || a.created_at)
      );
      setHistory(combined);
    } catch (err) {
      setError(err.message || "Failed to retrieve approval history.");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchHistory();
  }, []);

  const filtered = history.filter((item) => {
    if (filter === "ALL") return true;
    return item.status === filter;
  });

  return (
    <div className="panel">
      <div className="panel-header">
        <div>
          <h2 className="panel-title">Approval History</h2>
          <p className="panel-subtitle">
            Permanent audit record of previously approved and rejected sensitive requests
          </p>
        </div>
        <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
          {["ALL", "APPROVED", "REJECTED"].map((s) => (
            <button
              key={s}
              className={`btn btn-sm ${filter === s ? "btn-primary" : "btn-secondary"}`}
              onClick={() => setFilter(s)}
            >
              {s === "ALL" ? "All" : s === "APPROVED" ? "Approved" : "Rejected"}
            </button>
          ))}
          <button className="btn btn-secondary btn-sm" onClick={fetchHistory} disabled={loading}>
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

        {filtered.length === 0 && !loading && (
          <div style={{ padding: "48px 20px", textAlign: "center", color: "var(--text-muted)" }}>
            <FileText size={32} style={{ margin: "0 auto 12px", opacity: 0.5 }} />
            <p style={{ fontSize: 14, fontWeight: 600, color: "var(--text-main)" }}>
              No Resolved Approvals Yet
            </p>
            <p style={{ fontSize: 12 }}>
              Approved and rejected decisions will be permanently recorded here with reviewer identity and timestamps.
            </p>
          </div>
        )}

        {filtered.length > 0 && (
          <div className="table-responsive">
            <table className="data-table">
              <thead>
                <tr>
                  <th>Service &amp; Operation</th>
                  <th>Decision</th>
                  <th>Requester</th>
                  <th>Reviewed By</th>
                  <th>Decided At</th>
                  <th>Notes / Rejection Reason</th>
                </tr>
              </thead>
              <tbody>
                {filtered.map((h) => (
                  <tr key={h.id}>
                    <td>
                      <div style={{ fontSize: 11, color: "var(--text-muted)", marginBottom: 3 }}>
                        {h.api_name || "Registered Service"}
                      </div>
                      <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
                        <span className={`badge badge-method method-${h.http_method}`}>
                          {h.http_method}
                        </span>
                        <code style={{ fontFamily: "var(--font-mono)", fontSize: 12, fontWeight: 500 }}>
                          {h.endpoint_path}
                        </code>
                      </div>
                    </td>
                    <td>
                      {h.status === "APPROVED" ? (
                        <span className="badge badge-safe">
                          <CheckCircle2 size={11} />
                          <span>APPROVED</span>
                        </span>
                      ) : (
                        <span className="badge badge-danger">
                          <XCircle size={11} />
                          <span>REJECTED</span>
                        </span>
                      )}
                    </td>
                    <td style={{ fontSize: 12, fontWeight: 600 }}>
                      {h.requested_by_username || "Unknown"}
                    </td>
                    <td style={{ fontSize: 12, color: "var(--text-main)" }}>
                      {h.decided_by_username || "—"}
                    </td>
                    <td style={{ fontSize: 12, color: "var(--text-muted)" }}>
                      {h.decided_at ? new Date(h.decided_at).toLocaleString() : "—"}
                    </td>
                    <td style={{ fontSize: 12, color: "var(--text-muted)", maxWidth: 280 }}>
                      {h.status === "REJECTED" && h.rejection_reason ? (
                        <span style={{ color: "var(--danger-text)", fontWeight: 500 }}>
                          {h.rejection_reason}
                        </span>
                      ) : (
                        h.classification_reason
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
