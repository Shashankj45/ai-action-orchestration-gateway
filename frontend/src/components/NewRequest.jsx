import React, { useState } from "react";
import { Send, ArrowRight, CheckCircle2, Clock, AlertCircle, ShieldAlert, FileText } from "lucide-react";
import { api } from "../services/api";
import { normalizeResultDisplay, formatFieldValue } from "../utils/resultFormatter";

const EXAMPLE_REQUESTS = [
  "View reservation details for booking 105",
  "Cancel my booking 105",
  "Request late checkout for booking 105",
  "View reservation details for booking 404",
];

function ResultDetailsView({ resultData, isDemoResult }) {
  const normalized = normalizeResultDisplay(resultData);

  return (
    <div
      style={{
        borderRadius: 6,
        border: "1px solid var(--border-subtle)",
        backgroundColor: "var(--bg-surface)",
        overflow: "hidden",
      }}
    >
      <div
        style={{
          padding: "10px 14px",
          borderBottom: "1px solid var(--border-subtle)",
          backgroundColor: "var(--bg-app)",
          display: "flex",
          alignItems: "center",
          justifyContent: "space-between",
          gap: 8,
        }}
      >
        <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
          <FileText size={14} color="var(--primary)" />
          <strong style={{ fontSize: 13 }}>Result Details</strong>
        </div>
        {isDemoResult && (
          <span
            style={{
              fontSize: 10,
              fontWeight: 600,
              textTransform: "uppercase",
              letterSpacing: "0.04em",
              padding: "2px 6px",
              borderRadius: 4,
              backgroundColor: "#fef3c7",
              color: "#92400e",
              border: "1px solid #fde68a",
            }}
          >
            Demo Fixture
          </span>
        )}
      </div>

      {normalized.kind === "empty" && (
        <div style={{ padding: "14px", fontSize: 12, color: "var(--text-muted)" }}>
          The service completed your request with no additional details to display.
        </div>
      )}

      {normalized.kind === "record" && (
        <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 13 }}>
          <tbody>
            {normalized.rows.map((row, idx) => (
              <tr
                key={row.key}
                style={{
                  borderBottom:
                    idx < normalized.rows.length - 1 ? "1px solid var(--border-subtle)" : "none",
                }}
              >
                <td
                  style={{
                    padding: "9px 14px",
                    color: "var(--text-muted)",
                    width: "42%",
                    fontWeight: 500,
                  }}
                >
                  {row.label}
                </td>
                <td
                  style={{
                    padding: "9px 14px",
                    color: "var(--text-main)",
                    fontWeight: 600,
                    textAlign: "right",
                  }}
                >
                  {row.value}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}

      {normalized.kind === "table" && (
        <div className="table-responsive">
          <table className="data-table">
            <thead>
              <tr>
                {normalized.columns.map((col) => (
                  <th key={col.key}>{col.label}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {normalized.rows.map((row, rIdx) => (
                <tr key={rIdx}>
                  {normalized.columns.map((col) => (
                    <td key={col.key} style={{ fontSize: 12 }}>
                      {formatFieldValue(row[col.key])}
                    </td>
                  ))}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

export function NewRequest({ isDemo = false, onRequestSubmitted, onViewMyRequests, onViewHistory }) {
  const [requestText, setRequestText] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [outcome, setOutcome] = useState(null);
  const [error, setError] = useState(null);

  const handleSubmit = async (e) => {
    e?.preventDefault();
    if (!requestText.trim() || submitting) return;

    setSubmitting(true);
    setError(null);
    setOutcome(null);

    try {
      const response = await api.processTask(requestText.trim());
      setOutcome(response);
      if (onRequestSubmitted) onRequestSubmitted();
    } catch (err) {
      setError(err.message || "Unable to submit your request right now. Please try again.");
    } finally {
      setSubmitting(false);
    }
  };

  const isSafeSuccess =
    outcome?.status === "EXECUTED_SAFE" && outcome?.execution_status !== "FAILED";
  const isSafeFailure =
    outcome?.status === "EXECUTED_SAFE" && outcome?.execution_status === "FAILED";

  return (
    <div style={{ display: "grid", gridTemplateColumns: "1.1fr 1.05fr", gap: 24, alignItems: "start" }}>
      {/* Left: Natural-Language Request Composer */}
      <div className="panel">
        <div className="panel-header">
          <div>
            <h2 className="panel-title">New Request</h2>
            <p className="panel-subtitle">
              Describe what you would like to accomplish in plain language
            </p>
          </div>
        </div>

        <div className="panel-body">
          <form onSubmit={handleSubmit}>
            <div className="form-group">
              <label className="form-label" htmlFor="user-request-input">
                What would you like to do?
              </label>
              <textarea
                id="user-request-input"
                rows={4}
                required
                className="form-textarea"
                style={{ fontFamily: "var(--font-sans)", fontSize: 14 }}
                value={requestText}
                onChange={(e) => setRequestText(e.target.value)}
                placeholder="Describe your request clearly, including any reference numbers or details..."
              />
            </div>

            <div style={{ marginBottom: 16 }}>
              <span style={{ fontSize: 12, color: "var(--text-muted)", display: "block", marginBottom: 6 }}>
                Example requests:
              </span>
              <div style={{ display: "flex", flexWrap: "wrap", gap: 6 }}>
                {EXAMPLE_REQUESTS.map((example, idx) => (
                  <button
                    key={idx}
                    type="button"
                    className="btn btn-secondary btn-sm"
                    style={{ fontSize: 11 }}
                    onClick={() => setRequestText(example)}
                  >
                    {example}
                  </button>
                ))}
              </div>
            </div>

            <div style={{ display: "flex", justifyContent: "flex-end" }}>
              <button
                type="submit"
                className="btn btn-primary"
                disabled={submitting || !requestText.trim()}
              >
                <Send size={13} />
                <span>{submitting ? "Submitting..." : "Submit Request"}</span>
              </button>
            </div>
          </form>
        </div>
      </div>

      {/* Right: Plain-Language Request Status & Structured Result Details */}
      <div className="panel">
        <div className="panel-header">
          <div>
            <h2 className="panel-title">Request Status &amp; Results</h2>
            <p className="panel-subtitle">Progress update and structured details returned for your request</p>
          </div>
        </div>

        <div className="panel-body">
          {error && (
            <div className="alert-banner error">
              <AlertCircle size={16} />
              <div>
                <strong>Submission Error</strong>
                <div style={{ fontSize: 12, marginTop: 2 }}>{error}</div>
              </div>
            </div>
          )}

          {!outcome && !error && !submitting && (
            <div style={{ textAlign: "center", padding: "44px 16px", color: "var(--text-dim)" }}>
              <Clock size={28} style={{ margin: "0 auto 10px", opacity: 0.5 }} />
              <p style={{ fontSize: 13, color: "var(--text-muted)", marginBottom: 4 }}>
                No request submitted yet
              </p>
              <p style={{ fontSize: 12 }}>
                Standard read requests return structured details immediately. Sensitive changes are routed to an approver for review.
              </p>
            </div>
          )}

          {submitting && (
            <div style={{ textAlign: "center", padding: "44px 16px", color: "var(--text-muted)" }}>
              <p style={{ fontSize: 13, fontWeight: 500 }}>Processing your request...</p>
              <p style={{ fontSize: 12, marginTop: 4 }}>
                Checking requirements and routing your request.
              </p>
            </div>
          )}

          {outcome && (
            <div style={{ display: "flex", flexDirection: "column", gap: 16 }}>
              {outcome.status === "AWAITING_APPROVAL" && (
                <div className="alert-banner warning">
                  <ShieldAlert size={18} />
                  <div>
                    <strong style={{ display: "block", marginBottom: 4 }}>
                      Awaiting Approval
                    </strong>
                    <span style={{ fontSize: 13 }}>
                      Your request has been received and requires review by an authorized approver before it is carried out.
                    </span>
                  </div>
                </div>
              )}

              {isSafeSuccess && (
                <div className="alert-banner success">
                  <CheckCircle2 size={18} />
                  <div>
                    <strong style={{ display: "block", marginBottom: 4 }}>
                      Request Completed
                    </strong>
                    <span style={{ fontSize: 13 }}>
                      {outcome.message || "Your request was processed and completed successfully."}
                    </span>
                  </div>
                </div>
              )}

              {isSafeFailure && (
                <div className="alert-banner error">
                  <AlertCircle size={18} />
                  <div>
                    <strong style={{ display: "block", marginBottom: 4 }}>
                      Request Could Not Be Completed
                    </strong>
                    <span style={{ fontSize: 13 }}>
                      {outcome.message || "The service returned an error while processing your request."}
                    </span>
                  </div>
                </div>
              )}

              {outcome.status !== "AWAITING_APPROVAL" && outcome.status !== "EXECUTED_SAFE" && (
                <div className="alert-banner error">
                  <AlertCircle size={18} />
                  <div>
                    <strong style={{ display: "block", marginBottom: 4 }}>
                      Unable to Process Request
                    </strong>
                    <span style={{ fontSize: 13 }}>
                      {outcome.message || "We could not match your request to an available service. Please try rephrasing with more detail."}
                    </span>
                  </div>
                </div>
              )}

              {/* Simple Summary Card (No HTTP methods, paths, or raw request payloads) */}
              {(outcome.status === "AWAITING_APPROVAL" || outcome.status === "EXECUTED_SAFE") && (
                <div
                  style={{
                    padding: 14,
                    borderRadius: 6,
                    border: "1px solid var(--border-subtle)",
                    backgroundColor: "var(--bg-app)",
                    fontSize: 13,
                    display: "flex",
                    flexDirection: "column",
                    gap: 8,
                  }}
                >
                  {outcome.api_name && (
                    <div style={{ display: "flex", justifyContent: "space-between" }}>
                      <span style={{ color: "var(--text-muted)" }}>Service</span>
                      <strong>{outcome.api_name}</strong>
                    </div>
                  )}
                  <div style={{ display: "flex", justifyContent: "space-between" }}>
                    <span style={{ color: "var(--text-muted)" }}>Status</span>
                    <strong>
                      {outcome.status === "AWAITING_APPROVAL"
                        ? "Pending Approver Review"
                        : isSafeFailure
                        ? "Failed"
                        : "Completed"}
                    </strong>
                  </div>
                  {outcome.approval_id && (
                    <div style={{ display: "flex", justifyContent: "space-between" }}>
                      <span style={{ color: "var(--text-muted)" }}>Reference</span>
                      <code style={{ fontFamily: "var(--font-mono)", fontSize: 12 }}>
                        {outcome.approval_id.slice(0, 8)}
                      </code>
                    </div>
                  )}
                  {outcome.duration_ms !== null && outcome.duration_ms !== undefined && (
                    <div style={{ display: "flex", justifyContent: "space-between" }}>
                      <span style={{ color: "var(--text-muted)" }}>Response Time</span>
                      <span>{Math.round(outcome.duration_ms)} ms</span>
                    </div>
                  )}
                </div>
              )}

              {/* Structured Result Details Section (for completed safe operations) */}
              {isSafeSuccess && (
                <ResultDetailsView
                  resultData={outcome.result_data}
                  isDemoResult={Boolean(outcome.is_demo_result ?? isDemo)}
                />
              )}

              <div style={{ display: "flex", gap: 8, justifyContent: "flex-end" }}>
                {outcome.status === "AWAITING_APPROVAL" && onViewMyRequests && (
                  <button className="btn btn-primary btn-sm" onClick={onViewMyRequests}>
                    <span>Track in My Requests</span>
                    <ArrowRight size={13} />
                  </button>
                )}
                {outcome.status === "EXECUTED_SAFE" && onViewHistory && (
                  <button className="btn btn-secondary btn-sm" onClick={onViewHistory}>
                    <span>View Request History</span>
                    <ArrowRight size={13} />
                  </button>
                )}
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
