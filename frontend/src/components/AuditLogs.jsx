import React, { useState } from "react";
import { RotateCw, Eye, CheckCircle2, AlertTriangle, Clock, ArrowRight } from "lucide-react";
import { api } from "../services/api";

export function AuditLogs({ logs, onReload, onSwitchToApprovals, userRole, isDemo = false }) {
  const [selectedLog, setSelectedLog] = useState(null);
  const [statusFilter, setStatusFilter] = useState("ALL");
  const [replayingId, setReplayingId] = useState(null);
  const [replayNotice, setReplayNotice] = useState(null);

  const canReplay = !isDemo && (userRole === "APPROVER" || userRole === "ADMIN");

  const filteredLogs = logs.filter((log) => {
    if (statusFilter === "ALL") return true;
    return log.status === statusFilter;
  });

  const handleReplay = async (logId) => {
    setReplayingId(logId);
    setReplayNotice(null);

    try {
      const res = await api.replayLog(logId);
      if (res.is_sensitive) {
        setReplayNotice({
          type: "warning",
          text: "Replay was classified as SENSITIVE and routed to the Approval Queue for human review.",
          showApprovalBtn: true,
        });
      } else {
        setReplayNotice({
          type: "success",
          text: `Safe operation replayed successfully. New Log ID: ${res.new_log_id?.slice(0, 8)}...`,
        });
      }
      onReload();
    } catch (err) {
      setReplayNotice({ type: "error", text: `Replay failed: ${err.message}` });
    } finally {
      setReplayingId(null);
    }
  };

  return (
    <div className="panel">
      <div className="panel-header">
        <div>
          <h2 className="panel-title">
            {userRole === "APPROVER" ? "Request Logs" : "Execution Logs"}
          </h2>
          <p className="panel-subtitle">
            {userRole === "APPROVER"
              ? "Approval-linked executions and failed request records scoped to review governance"
              : "System-wide immutable audit trail of all executed operations"}
          </p>
        </div>

        {/* Filter Controls */}
        <div style={{ display: "flex", gap: 8 }}>
          {["ALL", "SUCCESS", "FAILED"].map((s) => (
            <button
              key={s}
              className={`btn btn-sm ${statusFilter === s ? "btn-primary" : "btn-secondary"}`}
              onClick={() => setStatusFilter(s)}
            >
              {s}
            </button>
          ))}
        </div>
      </div>

      <div className="panel-body" style={{ padding: 0 }}>
        {replayNotice && (
          <div style={{ padding: "16px 24px 0" }}>
            <div className={`alert-banner ${replayNotice.type}`}>
              <div>
                <span>{replayNotice.text}</span>
                {replayNotice.showApprovalBtn && (
                  <button
                    className="btn btn-secondary btn-sm"
                    style={{ marginLeft: 12, display: "inline-flex" }}
                    onClick={onSwitchToApprovals}
                  >
                    <span>View Approvals</span>
                    <ArrowRight size={12} />
                  </button>
                )}
              </div>
            </div>
          </div>
        )}

        {filteredLogs.length === 0 ? (
          <div style={{ padding: "48px 24px", textAlign: "center", color: "var(--text-muted)" }}>
            <Clock size={32} strokeWidth={1.5} style={{ margin: "0 auto 12px", opacity: 0.5 }} />
            <p style={{ fontWeight: 500 }}>No Execution Logs Found</p>
            <p style={{ fontSize: 13, marginTop: 4 }}>
              Execute tasks from the Task Console to populate the audit trail.
            </p>
          </div>
        ) : (
          <table className="data-table">
            <thead>
              <tr>
                <th>Operation &amp; Endpoint</th>
                <th>Outcome</th>
                <th>HTTP Status</th>
                <th>Latency</th>
                <th>Timestamp</th>
                <th style={{ textAlign: "right" }}>Actions</th>
              </tr>
            </thead>
            <tbody>
              {filteredLogs.map((log) => (
                <tr key={log.id}>
                  <td>
                    <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                      <span className={`badge badge-method method-${log.http_method}`}>
                        {log.http_method}
                      </span>
                      <code style={{ fontFamily: "var(--font-mono)", fontSize: 13 }}>
                        {log.endpoint_path}
                      </code>
                    </div>
                  </td>
                  <td>
                    {log.status === "SUCCESS" ? (
                      <span className="badge badge-safe">
                        <CheckCircle2 size={10} />
                        <span>SUCCESS</span>
                      </span>
                    ) : (
                      <span className="badge badge-danger">
                        <AlertTriangle size={10} />
                        <span>FAILED</span>
                      </span>
                    )}
                  </td>
                  <td>
                    <span style={{ fontFamily: "var(--font-mono)", fontSize: 12 }}>
                      {log.response_status_code || "—"}
                    </span>
                  </td>
                  <td>
                    <span style={{ fontFamily: "var(--font-mono)", fontSize: 12 }}>
                      {log.duration_ms ? `${log.duration_ms}ms` : "—"}
                    </span>
                  </td>
                  <td>
                    <span style={{ fontSize: 12, color: "var(--text-muted)" }}>
                      {new Date(log.executed_at).toLocaleTimeString()}
                    </span>
                  </td>
                  <td style={{ textAlign: "right" }}>
                    <div style={{ display: "inline-flex", gap: 8 }}>
                      <button
                        className="btn btn-secondary btn-sm"
                        onClick={() => setSelectedLog(log)}
                        title="Inspect payload & response"
                      >
                        <Eye size={12} />
                        <span>Inspect</span>
                      </button>
                      {canReplay && (
                        <button
                          className="btn btn-secondary btn-sm"
                          disabled={replayingId === log.id}
                          onClick={() => handleReplay(log.id)}
                          title="Replay this operation safely"
                        >
                          <RotateCw size={12} />
                          <span>Replay</span>
                        </button>
                      )}
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      {/* Inspect Log Details Modal */}
      {selectedLog && (
        <div className="modal-overlay">
          <div className="modal-content">
            <div className="modal-header">
              <h3 style={{ fontSize: 15, fontWeight: 600 }}>Execution Audit Record</h3>
              <button
                className="btn btn-secondary btn-sm"
                style={{ border: "none", padding: "4px 8px" }}
                onClick={() => setSelectedLog(null)}
              >
                ✕
              </button>
            </div>

            <div className="modal-body">
              <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 10, fontSize: 13, marginBottom: 16 }}>
                <div>
                  <span style={{ color: "var(--text-muted)" }}>Log ID: </span>
                  <code style={{ fontFamily: "var(--font-mono)", fontSize: 11 }}>{selectedLog.id}</code>
                </div>
                <div>
                  <span style={{ color: "var(--text-muted)" }}>Execution Status: </span>
                  <strong>{selectedLog.status}</strong> (HTTP {selectedLog.response_status_code || "N/A"})
                </div>
                <div>
                  <span style={{ color: "var(--text-muted)" }}>Method &amp; Path: </span>
                  <code>{selectedLog.http_method} {selectedLog.endpoint_path}</code>
                </div>
                <div>
                  <span style={{ color: "var(--text-muted)" }}>Duration: </span>
                  <span>{selectedLog.duration_ms} ms</span>
                </div>
              </div>

              {selectedLog.error_message && (
                <div className="alert-banner error" style={{ marginBottom: 12 }}>
                  <AlertTriangle size={16} />
                  <span>{selectedLog.error_message}</span>
                </div>
              )}

              <div style={{ marginBottom: 16 }}>
                <label className="form-label">Request Parameters (Replayable):</label>
                <pre className="code-box">
                  {JSON.stringify(selectedLog.request_payload || {}, null, 2)}
                </pre>
              </div>

              <div>
                <label className="form-label">Response Body (Truncation Protected):</label>
                <pre className="code-box">
                  {JSON.stringify(selectedLog.response_body || {}, null, 2)}
                </pre>
              </div>
            </div>

            <div className="modal-footer">
              <button
                className="btn btn-secondary"
                onClick={() => setSelectedLog(null)}
              >
                Close
              </button>
              {canReplay && (
                <button
                  className="btn btn-primary"
                  disabled={replayingId === selectedLog.id}
                  onClick={() => {
                    handleReplay(selectedLog.id);
                    setSelectedLog(null);
                  }}
                >
                  <RotateCw size={12} />
                  <span>Replay Request</span>
                </button>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
