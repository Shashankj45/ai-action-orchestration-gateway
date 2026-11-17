import React, { useState } from "react";
import { Play, ArrowRight, ShieldCheck, ShieldAlert, AlertTriangle, CheckCircle2, Clock } from "lucide-react";
import { api } from "../services/api";

const QUICK_PROMPTS = [
  "Charge 50 dollars via Stripe",
  "Get temperature for London via Weather Service",
  "Send a payout of 250 dollars via Stripe",
];

export function TaskConsole({ onTaskCompleted, onSwitchToApprovals }) {
  const [prompt, setPrompt] = useState("");
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState(null);

  const handleSubmit = async (e) => {
    e?.preventDefault();
    if (!prompt.trim() || loading) return;

    setLoading(true);
    setError(null);
    setResult(null);

    try {
      const response = await api.processTask(prompt.trim());
      setResult(response);
      if (onTaskCompleted) onTaskCompleted();
    } catch (err) {
      setError(err.message || "Failed to process task.");
    } finally {
      setLoading(false);
    }
  };

  const handleSelectQuickPrompt = (p) => {
    setPrompt(p);
  };

  return (
    <div style={{ display: "grid", gridTemplateColumns: "1.1fr 1fr", gap: 24, alignItems: "start" }}>
      {/* Left Column: Input Form */}
      <div className="panel">
        <div className="panel-header">
          <div>
            <h2 className="panel-title">Task Orchestration Console</h2>
            <p className="panel-subtitle">
              Submit natural-language instructions to the AI action orchestrator
            </p>
          </div>
        </div>

        <div className="panel-body">
          <form onSubmit={handleSubmit}>
            <div className="form-group">
              <label className="form-label">Natural Language Request</label>
              <textarea
                rows={4}
                required
                className="form-textarea"
                style={{ fontFamily: "var(--font-sans)", fontSize: 14 }}
                value={prompt}
                onChange={(e) => setPrompt(e.target.value)}
                placeholder="e.g. Charge 75 dollars to customer via Stripe"
              />
            </div>

            <div style={{ marginBottom: 16 }}>
              <span style={{ fontSize: 12, color: "var(--text-muted)", display: "block", marginBottom: 6 }}>
                Quick Prompt Presets:
              </span>
              <div style={{ display: "flex", flexWrap: "wrap", gap: 6 }}>
                {QUICK_PROMPTS.map((qp, idx) => (
                  <button
                    key={idx}
                    type="button"
                    className="btn btn-secondary btn-sm"
                    style={{ fontSize: 11 }}
                    onClick={() => handleSelectQuickPrompt(qp)}
                  >
                    {qp}
                  </button>
                ))}
              </div>
            </div>

            <div style={{ display: "flex", justifyContent: "flex-end" }}>
              <button
                type="submit"
                className="btn btn-primary"
                disabled={loading || !prompt.trim()}
              >
                <Play size={13} fill="currentColor" />
                <span>{loading ? "Orchestrating..." : "Execute Instruction"}</span>
              </button>
            </div>
          </form>
        </div>
      </div>

      {/* Right Column: Execution Breakdown */}
      <div className="panel">
        <div className="panel-header">
          <div>
            <h2 className="panel-title">Orchestration &amp; Guardrail Pipeline</h2>
            <p className="panel-subtitle">Real-time inspection of resolution, safety check, and dispatch</p>
          </div>
        </div>

        <div className="panel-body">
          {error && (
            <div className="alert-banner error">
              <AlertTriangle size={16} />
              <div>
                <strong>Execution Error:</strong> {error}
              </div>
            </div>
          )}

          {!result && !error && !loading && (
            <div style={{ textAlign: "center", padding: "48px 12px", color: "var(--text-dim)" }}>
              <Clock size={28} style={{ margin: "0 auto 8px", opacity: 0.5 }} />
              <p style={{ fontSize: 13 }}>Awaiting input. Submit a task to view execution breakdown.</p>
            </div>
          )}

          {loading && (
            <div style={{ textAlign: "center", padding: "48px 12px", color: "var(--text-muted)" }}>
              <p style={{ fontSize: 13, fontWeight: 500 }}>1. Translating task with LLM...</p>
              <p style={{ fontSize: 12, marginTop: 4 }}>2. Checking parameter schemas &amp; safety classifier...</p>
            </div>
          )}

          {result && (
            <div>
              {/* Classification Outcome Banner */}
              {result.status === "AWAITING_APPROVAL" && (
                <div className="alert-banner warning">
                  <ShieldAlert size={18} />
                  <div>
                    <strong style={{ display: "block" }}>Action Held: SENSITIVE Operation</strong>
                    <span>{result.classification_reason || result.message}</span>
                    <div style={{ marginTop: 8 }}>
                      <button
                        className="btn btn-primary btn-sm"
                        onClick={onSwitchToApprovals}
                      >
                        <span>Open Approval Queue</span>
                        <ArrowRight size={12} />
                      </button>
                    </div>
                  </div>
                </div>
              )}

              {result.status === "EXECUTED_SAFE" && (
                <div className="alert-banner success">
                  <CheckCircle2 size={18} />
                  <div>
                    <strong style={{ display: "block" }}>Auto-Executed: SAFE Operation</strong>
                    <span>{result.message} (Round-trip: {result.duration_ms}ms)</span>
                  </div>
                </div>
              )}

              {["NO_TOOLS", "NO_TOOL_SELECTED", "VALIDATION_FAILED", "INVALID_TOOL", "ERROR"].includes(result.status) && (
                <div className="alert-banner error">
                  <AlertTriangle size={18} />
                  <div>
                    <strong>Resolution Status: {result.status}</strong>
                    <div style={{ fontSize: 12, marginTop: 2 }}>{result.message}</div>
                  </div>
                </div>
              )}

              {/* Action Plan Details */}
              {result.endpoint_path && (
                <div style={{ marginTop: 16 }}>
                  <h4 style={{ fontSize: 12, textTransform: "uppercase", letterSpacing: "0.04em", color: "var(--text-muted)", marginBottom: 8 }}>
                    Action Plan Metadata
                  </h4>

                  <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 8, fontSize: 13, marginBottom: 12 }}>
                    <div>
                      <span style={{ color: "var(--text-muted)" }}>Target Service: </span>
                      <strong>{result.api_name || "—"}</strong>
                    </div>
                    <div>
                      <span style={{ color: "var(--text-muted)" }}>HTTP Method: </span>
                      <span className={`badge badge-method method-${result.http_method}`}>
                        {result.http_method}
                      </span>
                    </div>
                    <div style={{ gridColumn: "1 / -1" }}>
                      <span style={{ color: "var(--text-muted)" }}>Path: </span>
                      <code style={{ fontFamily: "var(--font-mono)", fontSize: 12 }}>{result.endpoint_path}</code>
                    </div>
                  </div>

                  <h4 style={{ fontSize: 12, textTransform: "uppercase", letterSpacing: "0.04em", color: "var(--text-muted)", marginBottom: 6 }}>
                    Validated Request Payload
                  </h4>
                  <pre className="code-box">
                    {JSON.stringify(result.request_payload || {}, null, 2)}
                  </pre>

                  {result.response_body && (
                    <div style={{ marginTop: 12 }}>
                      <h4 style={{ fontSize: 12, textTransform: "uppercase", letterSpacing: "0.04em", color: "var(--text-muted)", marginBottom: 6 }}>
                        API Response Body (Status: {result.response_status_code})
                      </h4>
                      <pre className="code-box">
                        {JSON.stringify(result.response_body, null, 2)}
                      </pre>
                    </div>
                  )}
                </div>
              )}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
