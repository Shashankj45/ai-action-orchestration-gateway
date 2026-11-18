import React, { useState } from "react";
import { CheckCircle2, AlertCircle, Clock, RefreshCw, ArrowRight } from "lucide-react";
import { normalizeResultDisplay } from "../utils/resultFormatter";

export function RequestHistory({ logs, onReload, onNewRequest }) {
  const [filter, setFilter] = useState("ALL");
  const [selected, setSelected] = useState(null);

  const filtered = (logs || []).filter((item) => {
    if (filter === "ALL") return true;
    return item.status === filter;
  });

  return (
    <div className="panel">
      <div className="panel-header">
        <div>
          <h2 className="panel-title">Request History</h2>
          <p className="panel-subtitle">
            Completed and failed outcomes for requests submitted from your account
          </p>
        </div>

        <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
          {["ALL", "SUCCESS", "FAILED"].map((s) => (
            <button
              key={s}
              className={`btn btn-sm ${filter === s ? "btn-primary" : "btn-secondary"}`}
              onClick={() => setFilter(s)}
            >
              {s === "ALL" ? "All" : s === "SUCCESS" ? "Completed" : "Failed"}
            </button>
          ))}
          {onReload && (
            <button className="btn btn-secondary btn-sm" onClick={onReload}>
              <RefreshCw size={13} />
              <span>Refresh</span>
            </button>
          )}
        </div>
      </div>

      <div className="panel-body" style={{ padding: 0 }}>
        {filtered.length === 0 ? (
          <div style={{ padding: "48px 24px", textAlign: "center", color: "var(--text-muted)" }}>
            <Clock size={32} strokeWidth={1.5} style={{ margin: "0 auto 12px", opacity: 0.5 }} />
            <p style={{ fontWeight: 600, color: "var(--text-main)", fontSize: 14 }}>
              No Request History Yet
            </p>
            <p style={{ fontSize: 12, marginTop: 4, marginBottom: 16 }}>
              Once your requests are completed, their results will appear here.
            </p>
            {onNewRequest && (
              <button className="btn btn-primary btn-sm" onClick={onNewRequest}>
                <span>Submit a Request</span>
                <ArrowRight size={13} />
              </button>
            )}
          </div>
        ) : (
          <div className="table-responsive">
            <table className="data-table">
              <thead>
                <tr>
                  <th>Reference</th>
                  <th>Service</th>
                  <th>Outcome</th>
                  <th>Type</th>
                  <th>Completed At</th>
                  <th style={{ textAlign: "right" }}>Details</th>
                </tr>
              </thead>
              <tbody>
                {filtered.map((item) => (
                  <tr key={item.id}>
                    <td>
                      <code style={{ fontFamily: "var(--font-mono)", fontSize: 12 }}>
                        {item.id.slice(0, 8)}
                      </code>
                    </td>
                    <td style={{ fontWeight: 500, fontSize: 13 }}>
                      {item.api_name || "Connected Service"}
                    </td>
                    <td>
                      {item.status === "SUCCESS" ? (
                        <span className="badge badge-safe">
                          <CheckCircle2 size={11} />
                          <span>Completed</span>
                        </span>
                      ) : (
                        <span className="badge badge-danger">
                          <AlertCircle size={11} />
                          <span>Failed</span>
                        </span>
                      )}
                    </td>
                    <td style={{ fontSize: 12, color: "var(--text-muted)" }}>
                      {item.approval_request_id ? "Approved Request" : "Standard Request"}
                    </td>
                    <td style={{ fontSize: 12, color: "var(--text-muted)" }}>
                      {new Date(item.executed_at).toLocaleString()}
                    </td>
                    <td style={{ textAlign: "right" }}>
                      <button
                        className="btn btn-secondary btn-sm"
                        onClick={() => setSelected(item)}
                      >
                        View
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Plain-English Detail Modal (No raw HTTP payloads or paths) */}
      {selected && (
        <div className="modal-overlay">
          <div className="modal-content" style={{ maxWidth: 480 }}>
            <div className="modal-header">
              <h3 style={{ fontSize: 15, fontWeight: 600 }}>Request Summary</h3>
              <button
                className="btn btn-secondary btn-sm"
                style={{ border: "none", padding: "4px 8px" }}
                onClick={() => setSelected(null)}
              >
                ✕
              </button>
            </div>

            <div className="modal-body" style={{ display: "flex", flexDirection: "column", gap: 12, fontSize: 13 }}>
              <div style={{ display: "flex", justifyContent: "space-between", borderBottom: "1px solid var(--border-subtle)", paddingBottom: 8 }}>
                <span style={{ color: "var(--text-muted)" }}>Reference ID</span>
                <code style={{ fontFamily: "var(--font-mono)", fontSize: 12 }}>{selected.id.slice(0, 8)}</code>
              </div>
              <div style={{ display: "flex", justifyContent: "space-between", borderBottom: "1px solid var(--border-subtle)", paddingBottom: 8 }}>
                <span style={{ color: "var(--text-muted)" }}>Service</span>
                <strong>{selected.api_name || "Connected Service"}</strong>
              </div>
              <div style={{ display: "flex", justifyContent: "space-between", borderBottom: "1px solid var(--border-subtle)", paddingBottom: 8 }}>
                <span style={{ color: "var(--text-muted)" }}>Outcome</span>
                <strong>{selected.status === "SUCCESS" ? "Completed Successfully" : "Failed"}</strong>
              </div>
              <div style={{ display: "flex", justifyContent: "space-between", borderBottom: "1px solid var(--border-subtle)", paddingBottom: 8 }}>
                <span style={{ color: "var(--text-muted)" }}>Authorization</span>
                <span>{selected.approval_request_id ? "Reviewed and Approved" : "Automatic (Standard Request)"}</span>
              </div>
              <div style={{ display: "flex", justifyContent: "space-between" }}>
                <span style={{ color: "var(--text-muted)" }}>Completed At</span>
                <span>{new Date(selected.executed_at).toLocaleString()}</span>
              </div>

              {selected.status === "SUCCESS" && (() => {
                const normalized = normalizeResultDisplay(selected.result_data);
                if (normalized.kind !== "record") return null;
                return (
                  <div
                    style={{
                      marginTop: 4,
                      borderRadius: 6,
                      border: "1px solid var(--border-subtle)",
                      overflow: "hidden",
                    }}
                  >
                    <div
                      style={{
                        padding: "8px 12px",
                        backgroundColor: "var(--bg-app)",
                        borderBottom: "1px solid var(--border-subtle)",
                        display: "flex",
                        justifyContent: "space-between",
                        alignItems: "center",
                        fontSize: 12,
                        fontWeight: 600,
                      }}
                    >
                      <span>Result Details</span>
                      {selected.is_demo_result && (
                        <span style={{ fontSize: 10, color: "#92400e", textTransform: "uppercase" }}>
                          Demo Fixture
                        </span>
                      )}
                    </div>
                    <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 12 }}>
                      <tbody>
                        {normalized.rows.map((row, idx) => (
                          <tr
                            key={row.key}
                            style={{
                              borderBottom:
                                idx < normalized.rows.length - 1
                                  ? "1px solid var(--border-subtle)"
                                  : "none",
                            }}
                          >
                            <td style={{ padding: "7px 12px", color: "var(--text-muted)" }}>{row.label}</td>
                            <td style={{ padding: "7px 12px", textAlign: "right", fontWeight: 600 }}>
                              {row.value}
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                );
              })()}

              {selected.error_message && (
                <div className="alert-banner error" style={{ marginTop: 4 }}>
                  <AlertCircle size={15} />
                  <span>{selected.error_message}</span>
                </div>
              )}
            </div>

            <div className="modal-footer">
              <button className="btn btn-secondary" onClick={() => setSelected(null)}>
                Close
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
