/**
 * src/utils/resultFormatter.js
 *
 * Formats sanitized structured result data returned by POST /tasks and GET /logs
 * into clean human-readable labels and display rows for the User Dashboard.
 */

const ACRONYMS = new Set(["id", "usd", "eur", "gbp", "utc", "eta", "sku", "pin"]);

export function formatFieldLabel(key) {
  if (!key) return "";
  return String(key)
    .replace(/([a-z])([A-Z])/g, "$1 $2")
    .replace(/[_-]+/g, " ")
    .trim()
    .split(/\s+/)
    .map((word) => {
      const lower = word.toLowerCase();
      if (ACRONYMS.has(lower)) return lower.toUpperCase();
      return lower.charAt(0).toUpperCase() + lower.slice(1);
    })
    .join(" ");
}

export function formatFieldValue(value) {
  if (value === null || value === undefined) return "—";
  if (typeof value === "boolean") return value ? "Yes" : "No";
  if (typeof value === "number" || typeof value === "string") return String(value);
  if (Array.isArray(value)) {
    const primitives = value.filter((v) => v !== null && v !== undefined && typeof v !== "object");
    if (primitives.length === value.length) {
      return primitives.join(", ");
    }
    return `${value.length} item${value.length === 1 ? "" : "s"}`;
  }
  if (typeof value === "object") {
    return Object.entries(value)
      .map(([k, v]) => `${formatFieldLabel(k)}: ${formatFieldValue(v)}`)
      .join(" | ");
  }
  return String(value);
}

/**
 * Normalizes sanitized result_data into either:
 * - { kind: "empty" }
 * - { kind: "record", rows: Array<{ key, label, value }> }
 * - { kind: "table", columns: Array<{ key, label }>, rows: Array<object> }
 */
export function normalizeResultDisplay(resultData) {
  if (resultData === null || resultData === undefined) {
    return { kind: "empty" };
  }

  if (Array.isArray(resultData)) {
    if (resultData.length === 0) return { kind: "empty" };
    const allObjects = resultData.every((item) => item && typeof item === "object" && !Array.isArray(item));
    if (allObjects) {
      const colKeys = Array.from(
        new Set(resultData.flatMap((item) => Object.keys(item)))
      ).slice(0, 8);
      if (colKeys.length === 0) return { kind: "empty" };
      return {
        kind: "table",
        columns: colKeys.map((key) => ({ key, label: formatFieldLabel(key) })),
        rows: resultData,
      };
    }
    return {
      kind: "record",
      rows: resultData.map((val, idx) => ({
        key: String(idx),
        label: `Item ${idx + 1}`,
        value: formatFieldValue(val),
      })),
    };
  }

  if (typeof resultData === "object") {
    const entries = Object.entries(resultData).filter(
      ([, v]) => v !== null && v !== undefined && v !== ""
    );
    if (entries.length === 0) return { kind: "empty" };
    return {
      kind: "record",
      rows: entries.map(([key, val]) => ({
        key,
        label: formatFieldLabel(key),
        value: formatFieldValue(val),
      })),
    };
  }

  return {
    kind: "record",
    rows: [{ key: "value", label: "Result", value: formatFieldValue(resultData) }],
  };
}
