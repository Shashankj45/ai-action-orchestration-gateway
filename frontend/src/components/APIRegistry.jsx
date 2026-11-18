import React, { useState } from "react";
import { Plus, Trash2, Key, ShieldAlert, Globe, Server, Check, AlertCircle } from "lucide-react";
import { api } from "../services/api";

const PRESET_TEMPLATES = {
  stripe: {
    name: "Stripe Payments",
    base_url: "https://api.stripe.com",
    description: "Core payment processing and transfer API",
    auth_header_name: "Authorization",
    auth_header_value: "Bearer sk_test_sampleToken123",
    is_sensitive: true,
    endpoints: JSON.stringify(
      [
        {
          path: "/v1/charges",
          method: "POST",
          description: "Create a charge or payment transfer",
          parameters: {
            amount: { type: "integer", required: true, description: "Amount in cents" },
            currency: { type: "string", required: false, default: "usd" },
          },
        },
      ],
      null,
      2
    ),
  },
  weather: {
    name: "Weather Service",
    base_url: "https://api.weatherapi.com",
    description: "Read-only global meteorological data",
    auth_header_name: "X-API-Key",
    auth_header_value: "weather_test_key_abc",
    is_sensitive: false,
    endpoints: JSON.stringify(
      [
        {
          path: "/v1/current",
          method: "GET",
          description: "Retrieve current temperature and weather for a city",
          parameters: {
            city: { type: "string", required: true, description: "City name" },
          },
        },
      ],
      null,
      2
    ),
  },
  hotel: {
    name: "Grand Hotel Reservations API",
    base_url: "https://httpbin.org",
    description: "Hotel room reservations, guest bookings, and cancellation management",
    auth_header_name: "Authorization",
    auth_header_value: "Bearer hotel_sec_token_9918",
    is_sensitive: false,
    endpoints: JSON.stringify(
      [
        {
          path: "/get",
          method: "GET",
          description: "View reservation details for booking 105",
          parameters: {
            booking_id: { type: "string", required: true, default: "105", description: "Booking confirmation number" },
          },
        },
        {
          path: "/post",
          method: "POST",
          description: "Cancel my booking 105 (Destructive customer action - Requires Manager Approval)",
          parameters: {
            booking_id: { type: "string", required: true, default: "105", description: "Booking number to cancel" },
            reason: { type: "string", required: false, default: "Customer requested cancellation", description: "Cancellation reason" },
          },
        },
      ],
      null,
      2
    ),
  },
};

export function APIRegistry({ apis, onReload, userRole, isDemo = false }) {
  const [modalOpen, setModalOpen] = useState(false);
  const [formData, setFormData] = useState(PRESET_TEMPLATES.stripe);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  const isAdmin = userRole === "ADMIN" && !isDemo;

  const handleApplyPreset = (key) => {
    setFormData(PRESET_TEMPLATES[key]);
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);
    setError(null);

    try {
      let parsedEndpoints = [];
      if (formData.endpoints) {
        parsedEndpoints = JSON.parse(formData.endpoints);
      }

      await api.createApi({
        name: formData.name,
        base_url: formData.base_url,
        description: formData.description,
        auth_header_name: formData.auth_header_name || null,
        auth_header_value: formData.auth_header_value || null,
        is_sensitive: formData.is_sensitive,
        endpoints: parsedEndpoints,
      });

      setModalOpen(false);
      onReload();
    } catch (err) {
      setError(err.message || "Failed to register API specification.");
    } finally {
      setLoading(false);
    }
  };

  const handleDelete = async (id, name) => {
    if (!window.confirm(`Deregister '${name}'? This will cascade-delete associated logs and approvals.`)) {
      return;
    }
    try {
      await api.deleteApi(id);
      onReload();
    } catch (err) {
      alert(`Deletion failed: ${err.message}`);
    }
  };

  return (
    <div className="panel">
      <div className="panel-header">
        <div>
          <h2 className="panel-title">Registered External APIs</h2>
          <p className="panel-subtitle">
            External REST services converted to AI function calling tool specifications
          </p>
        </div>
        {isAdmin ? (
          <button className="btn btn-primary" onClick={() => setModalOpen(true)}>
            <Plus size={14} />
            <span>Register New API</span>
          </button>
        ) : (
          <span className="badge badge-neutral" style={{ padding: "6px 12px", fontSize: 12 }}>
            {isDemo ? "Demo Admin — Read-Only" : "Read-Only (Admin Provisioned)"}
          </span>
        )}
      </div>

      <div className="panel-body" style={{ padding: 0 }}>
        {apis.length === 0 ? (
          <div style={{ padding: "48px 24px", textAlign: "center", color: "var(--text-muted)" }}>
            <Server size={32} strokeWidth={1.5} style={{ margin: "0 auto 12px", opacity: 0.5 }} />
            <p style={{ fontWeight: 500 }}>No External APIs Registered</p>
            <p style={{ fontSize: 13, marginTop: 4 }}>
              Register a service to convert its endpoints into safe AI tool definitions.
            </p>
            <button
              className="btn btn-secondary btn-sm"
              style={{ marginTop: 16 }}
              onClick={() => setModalOpen(true)}
            >
              Add First Service
            </button>
          </div>
        ) : (
          <table className="data-table">
            <thead>
              <tr>
                <th>Service Name</th>
                <th>Base URL</th>
                <th>Auth Protection</th>
                <th>Classification</th>
                <th>Endpoints</th>
                <th style={{ textAlign: "right" }}>Actions</th>
              </tr>
            </thead>
            <tbody>
              {apis.map((service) => (
                <tr key={service.id}>
                  <td>
                    <div style={{ fontWeight: 600 }}>{service.name}</div>
                    <div style={{ fontSize: 12, color: "var(--text-muted)" }}>{service.description || "—"}</div>
                  </td>
                  <td>
                    <span style={{ fontFamily: "var(--font-mono)", fontSize: 12 }}>
                      {service.base_url}
                    </span>
                  </td>
                  <td>
                    {service.has_auth ? (
                      <span className="badge badge-safe">
                        <Key size={10} />
                        <span>Encrypted (Fernet)</span>
                      </span>
                    ) : (
                      <span className="badge badge-neutral">No Auth Header</span>
                    )}
                  </td>
                  <td>
                    {service.is_sensitive ? (
                      <span className="badge badge-sensitive">
                        <ShieldAlert size={10} />
                        <span>Always Sensitive</span>
                      </span>
                    ) : (
                      <span className="badge badge-safe">Method-Determined</span>
                    )}
                  </td>
                  <td>
                    <span style={{ fontFamily: "var(--font-mono)", fontSize: 12 }}>
                      {service.endpoints?.length || 0} endpoint{service.endpoints?.length === 1 ? "" : "s"}
                    </span>
                  </td>
                  <td style={{ textAlign: "right" }}>
                    {isAdmin ? (
                      <button
                        className="btn btn-danger btn-sm"
                        onClick={() => handleDelete(service.id, service.name)}
                        title="Deregister API"
                      >
                        <Trash2 size={12} />
                        <span>Delete</span>
                      </button>
                    ) : (
                      <span style={{ fontSize: 12, color: "var(--text-muted)" }}>Protected</span>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      {modalOpen && (
        <div className="modal-overlay">
          <div className="modal-content">
            <div className="modal-header">
              <h3 style={{ fontSize: 15, fontWeight: 600 }}>Register External Service</h3>
              <button
                className="btn btn-secondary btn-sm"
                style={{ border: "none", padding: "4px 8px" }}
                onClick={() => setModalOpen(false)}
              >
                ✕
              </button>
            </div>

            <form onSubmit={handleSubmit}>
              <div className="modal-body">
                {error && (
                  <div className="alert-banner error">
                    <AlertCircle size={16} />
                    <span>{error}</span>
                  </div>
                )}

                <div style={{ marginBottom: 16 }}>
                  <label className="form-label" style={{ marginBottom: 4 }}>Template Presets</label>
                  <div style={{ display: "flex", gap: 8 }}>
                    <button
                      type="button"
                      className="btn btn-secondary btn-sm"
                      onClick={() => handleApplyPreset("stripe")}
                    >
                      Stripe Payments (Sensitive POST)
                    </button>
                    <button
                      type="button"
                      className="btn btn-secondary btn-sm"
                      onClick={() => handleApplyPreset("weather")}
                    >
                      Weather Service (Safe GET)
                    </button>
                    <button
                      type="button"
                      className="btn btn-secondary btn-sm"
                      onClick={() => handleApplyPreset("hotel")}
                    >
                      Hotel Bookings (Guest API)
                    </button>
                  </div>
                </div>

                <div className="form-group">
                  <label className="form-label">Service Identifier</label>
                  <input
                    type="text"
                    required
                    className="form-input"
                    value={formData.name}
                    onChange={(e) => setFormData({ ...formData, name: e.target.value })}
                    placeholder="e.g. Stripe API"
                  />
                </div>

                <div className="form-group">
                  <label className="form-label">
                    Base URL <span style={{ color: "var(--text-muted)", fontSize: 11 }}>(SSRF Protected)</span>
                  </label>
                  <input
                    type="url"
                    required
                    className="form-input"
                    value={formData.base_url}
                    onChange={(e) => setFormData({ ...formData, base_url: e.target.value })}
                    placeholder="https://api.stripe.com"
                  />
                </div>

                <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12 }}>
                  <div className="form-group">
                    <label className="form-label">Auth Header Name</label>
                    <input
                      type="text"
                      className="form-input"
                      value={formData.auth_header_name}
                      onChange={(e) => setFormData({ ...formData, auth_header_name: e.target.value })}
                      placeholder="e.g. Authorization"
                    />
                  </div>

                  <div className="form-group">
                    <label className="form-label">
                      Auth Secret <span style={{ color: "var(--text-muted)", fontSize: 11 }}>(Encrypted At Rest)</span>
                    </label>
                    <input
                      type="password"
                      className="form-input"
                      value={formData.auth_header_value}
                      onChange={(e) => setFormData({ ...formData, auth_header_value: e.target.value })}
                      placeholder="Bearer sk_live_..."
                    />
                  </div>
                </div>

                <div className="form-group">
                  <label style={{ display: "flex", alignItems: "center", gap: 8, cursor: "pointer", fontSize: 13 }}>
                    <input
                      type="checkbox"
                      checked={formData.is_sensitive}
                      onChange={(e) => setFormData({ ...formData, is_sensitive: e.target.checked })}
                    />
                    <span><strong>Force Sensitive Override</strong>: Require human approval for ALL actions on this API.</span>
                  </label>
                </div>

                <div className="form-group">
                  <label className="form-label">Endpoints Specification (JSON Schema)</label>
                  <textarea
                    rows={6}
                    className="form-textarea"
                    value={formData.endpoints}
                    onChange={(e) => setFormData({ ...formData, endpoints: e.target.value })}
                  />
                </div>
              </div>

              <div className="modal-footer">
                <button
                  type="button"
                  className="btn btn-secondary"
                  onClick={() => setModalOpen(false)}
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="btn btn-primary"
                  disabled={loading}
                >
                  {loading ? "Registering..." : "Save Service Specification"}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}
