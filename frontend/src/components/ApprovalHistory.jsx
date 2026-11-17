import React, { useState, useEffect } from "react";
import { CheckCircle2, XCircle, Clock, RefreshCw, FileText, AlertCircle } from "lucide-react";
import { api } from "../services/api";

export function ApprovalHistory() {
  const [history, setHistory] = useState([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  const fetchHistory = async () => {
    setLoading(true);
    setError(null);
    try {
      // Fetch all resolved approvals (approved or rejected)
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

  return (
    <div className="panel">
      <div className="panel-header">
        <div>
          <h2 className="panel-title">Hotel Supervisor Approval History</h2>
          <p className="panel-subtitle">Audit log of resolved sensitive guest requests and manager decisions</p>
        </div>
        <button className="btn btn-secondary btn-sm" onClick={fetchHistory} disabled={loading}>
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

        {history.length === 0 && !loading && (
          <div style={{ padding: "48px 20px", textAlign: "center", color: "var(--text-muted)" }}>
            <FileText size={32} style={{ margin: "0 auto 12px", opacity: 0.5 }} />
            <p style={{ fontSize: "14px", fontWeight: "600", color: "var(--text-main)" }}>No Resolved Approvals Yet</p>
            <p style={{ fontSize: "12px" }}>
              Decisions made on pending sensitive operations will be permanently logged here.
            </p>
          </div>
        )}

        {history.length > 0 && (
          <div className="table-responsive">
            <table className="data-table">
              <thead>
                <tr>
                  <th>Requested Action</th>
                  <th>Decision</th>
                  <th>Requester (Customer)</th>
                  <th>Decided By (Manager)</th>
                  <th>Decided At</th>
                  <th>Classification Reason</th>
                </tr>
              </thead>
              <tbody>
                {history.map((h) => (
                  <tr key={h.id}>
                    <td>
                      <div style={{ display: "flex", alignItems: "center", gap: "6px" }}>
                        <span className={`method-badge method-${h.http_method.toLowerCase()}`}>
                          {h.http_method}
                        </span>
                        <code style={{ fontSize: "12px", fontWeight: "600" }}>{h.endpoint_path}</code>
                      </div>
                    </td>
                    <td>
                      {h.status === "APPROVED" ? (
                        <span style={{ display: "inline-flex", alignItems: "center", gap: "4px", padding: "3px 8px", borderRadius: "4px", backgroundColor: "#dcfce7", color: "#166534", fontSize: "11px", fontWeight: "700" }}>
                          <CheckCircle2 size={12} />
                          <span>APPROVED</span>
                        </span>
                      ) : (
                        <span style={{ display: "inline-flex", alignItems: "center", gap: "4px", padding: "3px 8px", borderRadius: "4px", backgroundColor: "#fee2e2", color: "#991b1b", fontSize: "11px", fontWeight: "700" }}>
                          <XCircle size={12} />
                          <span>REJECTED</span>
                        </span>
                      )}
                    </td>
                    <td style={{ fontSize: "12px" }}>
                      <strong>{h.requested_by_username || "guest_customer"}</strong>
                    </td>
                    <td style={{ fontSize: "12px", color: "var(--text-main)" }}>
                      {h.decided_by_username || "hotel_manager"}
                    </td>
                    <td style={{ fontSize: "12px", color: "var(--text-dim)" }}>
                      {h.decided_at ? new Date(h.decided_at).toLocaleString() : "—"}
                    </td>
                    <td style={{ fontSize: "11px", color: "var(--text-muted)", maxWidth: "260px" }}>
                      {h.classification_reason}
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
