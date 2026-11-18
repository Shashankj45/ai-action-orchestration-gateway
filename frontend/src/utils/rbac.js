/**
 * src/utils/rbac.js
 *
 * Shared role display labels, navigation tab builders, and permission helpers
 * for the three-role dashboard architecture and Recruiter Demo Mode.
 */

export const ROLE_DISPLAY = {
  ADMIN: "Admin",
  APPROVER: "Approver",
  OPERATOR: "User",
};

export const DEMO_ROLE_OPTIONS = [
  {
    key: "user",
    backendRole: "OPERATOR",
    label: "Explore as User",
    shortLabel: "User",
    description: "Submit natural-language requests, track approval status, and view personal history",
  },
  {
    key: "approver",
    backendRole: "APPROVER",
    label: "Explore as Approver",
    shortLabel: "Approver",
    description: "Review pending sensitive requests, approve, or reject with a mandatory reason",
  },
  {
    key: "admin",
    backendRole: "ADMIN",
    label: "Explore as Admin",
    shortLabel: "Admin",
    description: "Inspect API registry, users, roles, security policies, logs, and monitoring (read-only)",
  },
];

export function getTabsForRole(role, pendingCount = 0) {
  switch (role) {
    case "ADMIN":
      return [
        { id: "overview", label: "Overview" },
        { id: "apis", label: "API Registry" },
        { id: "users", label: "User Management" },
        { id: "roles", label: "Role Management" },
        { id: "logs", label: "Execution Logs" },
        { id: "security", label: "Security & Policies" },
        { id: "monitoring", label: "System Monitoring" },
        { id: "settings", label: "Settings" },
      ];
    case "APPROVER":
      return [
        { id: "overview", label: "Overview" },
        { id: "approvals", label: "Pending Approvals", count: pendingCount, alert: pendingCount > 0 },
        { id: "approval_history", label: "Approval History" },
        { id: "request_logs", label: "Request Logs" },
        { id: "profile", label: "Profile" },
      ];
    case "OPERATOR":
    default:
      return [
        { id: "overview", label: "Overview" },
        { id: "new_request", label: "New Request" },
        { id: "my_requests", label: "My Requests", count: pendingCount > 0 ? pendingCount : undefined },
        { id: "request_history", label: "Request History" },
        { id: "profile", label: "Profile" },
      ];
  }
}

export function canAccessTab(role, tabId) {
  return getTabsForRole(role, 0).some((t) => t.id === tabId);
}

export function canMutateAdmin(user) {
  return Boolean(user && user.role === "ADMIN" && !user.is_demo);
}
