import React, { useState } from "react";
import { Check, X, ShieldAlert, Eye, Clock, AlertCircle } from "lucide-react";
import { api } from "../services/api";

export function ApprovalQueue({ approvals, onReload, userRole, currentUserId }) {
  const [selectedApproval, setSelectedApproval] = useState(null);
  const [processingId, setProcessingId] = useState(null);
  const [actionMessage, setActionMessage] = useState(null);

  const canDecide = userRole === "APPROVER" || userRole === "ADMIN";

  const handleApprove = async (id) => {
    setProcessingId(id);
    setActionMessage(null);
    try {
      const res = await api.approveRequest(id);
      setActionMessage({
        type: "success",
        text: `Operation approved and executed. Result status: ${res.execution?.status || "SUCCESS"}`,
      });
      onReload();
      setSelectedApproval(null);
    } catch (err) {
      setActionMessage({ type: "error", text: `Approval failed: ${err.message}` });
    } finally {
      setProcessingId(null);
    }
  };

  const handleReject = async (id) => {
    setProcessingId(id);
    setActionMessage(null);
    try {
      await api.rejectRequest(id);
      setActionMessage({ type: "warning", text: "Operation was rejected by user." });
      onReload();
      setSelectedApproval(null);
    } catch (err) {
      setActionMessage({ type: "error", text: `Rejection failed: ${err.message}` });
    } finally {
      setProcessingId(null);
    }
  };

  return (
    <div className="panel">
      <div className="panel-header">
        <div>
          <h2 className="panel-title">Human-in-the-Loop Approval Queue</h2>
          <p className="panel-subtitle">
            Sensitive or destructive AI actions awaiting explicit human verification
          </p>
        </div>
      </div>

      <div className="panel-body" style={{ padding: 0 }}>
        {actionMessage && (
          <div style={{ padding: "16px 24px 0" }}>
            <div className={`alert-banner ${actionMessage.type}`}>
              <span>{actionMessage.text}</span>
            </div>
          </div>
        )}

        {approvals.length === 0 ? (
          <div style={{ padding: "48px 24px", textAlign: "center", color: "var(--text-muted)" }}>
            <ShieldAlert size={32} strokeWidth={1.5} style={{ margin: "0 auto 12px", opacity: 0.5 }} />
            <p style={{ fontWeight: 500 }}>No Operations Awaiting Approval</p>
            <p style={{ fontSize: 13, marginTop: 4 }}>
              When the AI proposes a state-changing or sensitive action, it will appear here for review.
            </p>
          </div>
        ) : (
          <table className="data-table">
            <thead>
              <tr>
                <th>Operation &amp; Path</th>
                <th>Classification Reason</th>
                <th>Submitted</th>
                <th style={{ textAlign: "right" }}>Actions</th>
              </tr>
            </thead>
            <tbody>
              {approvals.map((req) => (
                <tr key={req.id}>
                  <td>
                    <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                      <span className={`badge badge-method method-${req.http_method}`}>
                        {req.http_method}
                      </span>
                      <code style={{ fontFamily: "var(--font-mono)", fontSize: 13, fontWeight: 500 }}>
                        {req.endpoint_path}
                      </code>
                    </div>
                  </td>
                  <td>
                    <span style={{ fontSize: 13, color: "var(--text-main)" }}>
                      {req.classification_reason}
                    </span>
                  </td>
                  <td>
                    <span style={{ fontSize: 12, color: "var(--text-muted)" }}>
                      {new Date(req.created_at).toLocaleTimeString()}
                    </span>
                  </td>
                  <td style={{ textAlign: "right" }}>
                    <div style={{ display: "inline-flex", gap: 8 }}>
                      <button
                        className="btn btn-secondary btn-sm"
                        onClick={() => setSelectedApproval(req)}
                      >
                        <Eye size={12} />
                        <span>Inspect</span>
                      </button>
                      {canDecide ? (
                        <>
                          {req.requested_by_user_id && req.requested_by_user_id === currentUserId ? (
                            <button
                              className="btn btn-secondary btn-sm"
                              disabled
                              title="Four-Eyes Principle: You requested this task and cannot self-approve it."
                            >
                              <span>Self-Locked</span>
                            </button>
                          ) : (
                            <button
                              className="btn btn-primary btn-sm"
                              disabled={processingId === req.id}
                              onClick={() => handleApprove(req.id)}
                            >
                              <Check size={12} />
                              <span>Approve</span>
                            </button>
                          )}
                          <button
                            className="btn btn-danger btn-sm"
                            disabled={processingId === req.id}
                            onClick={() => handleReject(req.id)}
                          >
                            <X size={12} />
                            <span>Reject</span>
                          </button>
                        </>
                      ) : (
                        <span style={{ fontSize: 12, color: "var(--text-muted)", alignSelf: "center" }}>
                          Requires Approver
                        </span>
                      )}
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      {/* Inspect Frozen Payload Modal */}
      {selectedApproval && (
        <div className="modal-overlay">
          <div className="modal-content">
            <div className="modal-header">
              <h3 style={{ fontSize: 15, fontWeight: 600 }}>Inspect Frozen Request Payload</h3>
              <button
                className="btn btn-secondary btn-sm"
                style={{ border: "none", padding: "4px 8px" }}
                onClick={() => setSelectedApproval(null)}
              >
                ✕
              </button>
            </div>

            <div className="modal-body">
              <div className="alert-banner warning" style={{ marginBottom: 16 }}>
                <AlertCircle size={16} />
                <span>
                  <strong>Immutable Action:</strong> What you see below is the exact payload frozen at task submission.
                  It cannot be modified before execution.
                </span>
              </div>

              <div style={{ marginBottom: 12, fontSize: 13 }}>
                <div><strong>Target Endpoint:</strong> {selectedApproval.http_method} {selectedApproval.endpoint_path}</div>
                <div><strong>Reason:</strong> {selectedApproval.classification_reason}</div>
              </div>

              <label className="form-label">Request Parameters (JSON):</label>
              <pre className="code-box">
                {JSON.stringify(selectedApproval.request_payload, null, 2)}
              </pre>
            </div>

            <div className="modal-footer">
              <button
                className="btn btn-secondary"
                onClick={() => setSelectedApproval(null)}
              >
                Close
              </button>
              <button
                className="btn btn-danger"
                disabled={processingId === selectedApproval.id}
                onClick={() => handleReject(selectedApproval.id)}
              >
                <X size={12} />
                <span>Reject</span>
              </button>
              <button
                className="btn btn-primary"
                disabled={processingId === selectedApproval.id}
                onClick={() => handleApprove(selectedApproval.id)}
              >
                <Check size={12} />
                <span>Approve &amp; Dispatch</span>
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
