import React, { useState } from "react";
import { Check, X, ShieldAlert, Eye, AlertCircle } from "lucide-react";
import { api } from "../services/api";

export function ApprovalQueue({ approvals, onReload, userRole, currentUserId }) {
  const [selectedApproval, setSelectedApproval] = useState(null);
  const [rejectTarget, setRejectTarget] = useState(null);
  const [rejectionReason, setRejectionReason] = useState("");
  const [rejectValidationError, setRejectValidationError] = useState(null);
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

  const openRejectModal = (req) => {
    setRejectTarget(req);
    setRejectionReason("");
    setRejectValidationError(null);
  };

  const handleConfirmReject = async (e) => {
    e.preventDefault();
    const trimmed = rejectionReason.trim();
    if (trimmed.length < 3) {
      setRejectValidationError("Please provide a rejection reason (at least 3 characters).");
      return;
    }

    setProcessingId(rejectTarget.id);
    setActionMessage(null);
    setRejectValidationError(null);
    try {
      await api.rejectRequest(rejectTarget.id, trimmed);
      setActionMessage({
        type: "warning",
        text: "Operation rejected and decision recorded in the audit history.",
      });
      onReload();
      setRejectTarget(null);
      setSelectedApproval(null);
      setRejectionReason("");
    } catch (err) {
      setRejectValidationError(err.message || "Rejection failed.");
    } finally {
      setProcessingId(null);
    }
  };

  const isSelfRequested = (req) =>
    Boolean(req?.requested_by_user_id && currentUserId && req.requested_by_user_id === currentUserId);

  return (
    <div className="panel">
      <div className="panel-header">
        <div>
          <h2 className="panel-title">Pending Approvals</h2>
          <p className="panel-subtitle">
            Review requested sensitive operations, parameters, and affected resources before authorization
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
            <p style={{ fontWeight: 600, color: "var(--text-main)" }}>No Pending Approvals</p>
            <p style={{ fontSize: 13, marginTop: 4 }}>
              When a user submits an operation requiring supervisor review, it will appear here.
            </p>
          </div>
        ) : (
          <div className="table-responsive">
            <table className="data-table">
              <thead>
                <tr>
                  <th>Requester</th>
                  <th>Service &amp; Operation</th>
                  <th>Why Approval Is Required</th>
                  <th>Submitted</th>
                  <th style={{ textAlign: "right" }}>Actions</th>
                </tr>
              </thead>
              <tbody>
                {approvals.map((req) => (
                  <tr key={req.id}>
                    <td style={{ fontSize: 13, fontWeight: 600 }}>
                      {req.requested_by_username || "Unknown User"}
                    </td>
                    <td>
                      <div style={{ fontSize: 12, color: "var(--text-muted)", marginBottom: 4 }}>
                        {req.api_name || "Registered Service"}
                      </div>
                      <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                        <span className={`badge badge-method method-${req.http_method}`}>
                          {req.http_method}
                        </span>
                        <code style={{ fontFamily: "var(--font-mono)", fontSize: 12, fontWeight: 500 }}>
                          {req.endpoint_path}
                        </code>
                      </div>
                    </td>
                    <td>
                      <span style={{ fontSize: 12, color: "var(--text-main)" }}>
                        {req.classification_reason}
                      </span>
                    </td>
                    <td>
                      <span style={{ fontSize: 12, color: "var(--text-muted)" }}>
                        {new Date(req.created_at).toLocaleString()}
                      </span>
                    </td>
                    <td style={{ textAlign: "right" }}>
                      <div style={{ display: "inline-flex", gap: 6 }}>
                        <button
                          className="btn btn-secondary btn-sm"
                          onClick={() => setSelectedApproval(req)}
                        >
                          <Eye size={12} />
                          <span>Inspect</span>
                        </button>
                        {canDecide && (
                          <>
                            {isSelfRequested(req) ? (
                              <button
                                className="btn btn-secondary btn-sm"
                                disabled
                                title="Four-Eyes Policy: You cannot approve your own request."
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
                              onClick={() => openRejectModal(req)}
                            >
                              <X size={12} />
                              <span>Reject</span>
                            </button>
                          </>
                        )}
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Inspect Frozen Payload Modal */}
      {selectedApproval && (
        <div className="modal-overlay">
          <div className="modal-content">
            <div className="modal-header">
              <h3 style={{ fontSize: 15, fontWeight: 600 }}>Inspect Sensitive Request</h3>
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
                  <strong>Frozen Operation Binding:</strong> Approving executes the exact operation and parameters shown below. They cannot be altered after submission.
                </span>
              </div>

              <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 10, marginBottom: 14, fontSize: 13 }}>
                <div>
                  <span style={{ color: "var(--text-muted)" }}>Submitted By: </span>
                  <strong>{selectedApproval.requested_by_username || "Unknown User"}</strong>
                </div>
                <div>
                  <span style={{ color: "var(--text-muted)" }}>Service: </span>
                  <strong>{selectedApproval.api_name || "Registered Service"}</strong>
                </div>
                <div style={{ gridColumn: "1 / -1" }}>
                  <span style={{ color: "var(--text-muted)" }}>Target Operation: </span>
                  <code>
                    {selectedApproval.http_method} {selectedApproval.endpoint_path}
                  </code>
                </div>
                <div style={{ gridColumn: "1 / -1" }}>
                  <span style={{ color: "var(--text-muted)" }}>Approval Requirement: </span>
                  <span>{selectedApproval.classification_reason}</span>
                </div>
              </div>

              <label className="form-label">Validated Request Parameters (JSON)</label>
              <pre className="code-box">
                {JSON.stringify(selectedApproval.request_payload || {}, null, 2)}
              </pre>
            </div>

            <div className="modal-footer">
              <button
                className="btn btn-secondary"
                onClick={() => setSelectedApproval(null)}
              >
                Close
              </button>
              {canDecide && (
                <>
                  <button
                    className="btn btn-danger"
                    disabled={processingId === selectedApproval.id}
                    onClick={() => openRejectModal(selectedApproval)}
                  >
                    <X size={12} />
                    <span>Reject</span>
                  </button>
                  {isSelfRequested(selectedApproval) ? (
                    <button
                      className="btn btn-secondary"
                      disabled
                      title="Four-Eyes Policy: You cannot approve your own request."
                    >
                      <span>Self-Approval Locked</span>
                    </button>
                  ) : (
                    <button
                      className="btn btn-primary"
                      disabled={processingId === selectedApproval.id}
                      onClick={() => handleApprove(selectedApproval.id)}
                    >
                      <Check size={12} />
                      <span>Approve &amp; Execute</span>
                    </button>
                  )}
                </>
              )}
            </div>
          </div>
        </div>
      )}

      {/* Rejection Reason Modal */}
      {rejectTarget && (
        <div className="modal-overlay">
          <div className="modal-content" style={{ maxWidth: 480 }}>
            <div className="modal-header">
              <h3 style={{ fontSize: 15, fontWeight: 600 }}>Reject Request</h3>
              <button
                className="btn btn-secondary btn-sm"
                style={{ border: "none", padding: "4px 8px" }}
                onClick={() => setRejectTarget(null)}
              >
                ✕
              </button>
            </div>

            <form onSubmit={handleConfirmReject}>
              <div className="modal-body">
                <p style={{ fontSize: 13, color: "var(--text-muted)", marginBottom: 12 }}>
                  Provide a clear reason for rejecting{" "}
                  <strong>{rejectTarget.requested_by_username || "this user"}</strong>&apos;s request (
                  <code>
                    {rejectTarget.http_method} {rejectTarget.endpoint_path}
                  </code>
                  ). This reason is permanently stored in the approval record and visible to the requester.
                </p>

                {rejectValidationError && (
                  <div className="alert-banner error" style={{ marginBottom: 12 }}>
                    <AlertCircle size={15} />
                    <span>{rejectValidationError}</span>
                  </div>
                )}

                <div className="form-group" style={{ marginBottom: 0 }}>
                  <label className="form-label" htmlFor="rejection-reason-input">
                    Rejection Reason (required, max 500 characters)
                  </label>
                  <textarea
                    id="rejection-reason-input"
                    rows={3}
                    required
                    maxLength={500}
                    className="form-textarea"
                    style={{ fontFamily: "var(--font-sans)", fontSize: 13 }}
                    value={rejectionReason}
                    onChange={(e) => setRejectionReason(e.target.value)}
                    placeholder="e.g. Booking window has expired or insufficient verification."
                  />
                </div>
              </div>

              <div className="modal-footer">
                <button
                  type="button"
                  className="btn btn-secondary"
                  onClick={() => setRejectTarget(null)}
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="btn btn-danger"
                  disabled={processingId === rejectTarget.id}
                >
                  <X size={12} />
                  <span>{processingId === rejectTarget.id ? "Rejecting..." : "Confirm Rejection"}</span>
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}
