import React, { useState, useEffect, useCallback } from "react";
import { Header } from "./components/Header";
import { Overview } from "./components/Overview";
import { APIRegistry } from "./components/APIRegistry";
import { TaskConsole } from "./components/TaskConsole";
import { ApprovalQueue } from "./components/ApprovalQueue";
import { ApprovalHistory } from "./components/ApprovalHistory";
import { MyRequests } from "./components/MyRequests";
import { AuditLogs } from "./components/AuditLogs";
import { UserManagement } from "./components/UserManagement";
import { SystemMonitoring } from "./components/SystemMonitoring";
import { Settings } from "./components/Settings";
import { Profile } from "./components/Profile";
import LoginModal from "./components/LoginModal";
import { api, setAuthToken, setOnUnauthorized } from "./services/api";

export function App() {
  const [currentUser, setCurrentUser] = useState(null);
  const [activeTab, setActiveTab] = useState("overview");
  const [apis, setApis] = useState([]);
  const [approvals, setApprovals] = useState([]);
  const [logs, setLogs] = useState([]);
  const [users, setUsers] = useState([]);

  // Handle automatic session expiration
  useEffect(() => {
    setOnUnauthorized(() => {
      setCurrentUser(null);
      setAuthToken(null);
    });
  }, []);

  const loadData = useCallback(async () => {
    if (!currentUser) return;
    try {
      const isOperator = currentUser.role === "OPERATOR";
      const isAdmin = currentUser.role === "ADMIN";
      const isApprover = currentUser.role === "APPROVER";

      const [apiList, approvalList, logList, userList] = await Promise.all([
        api.listApis().catch(() => []),
        isOperator
          ? api.listMyRequests().catch(() => [])
          : api.listApprovals({ status: "PENDING" }).catch(() => []),
        isApprover
          ? api.listLogs({ only_approvals: true }).catch(() => [])
          : api.listLogs().catch(() => []),
        isAdmin ? api.listUsers().catch(() => []) : Promise.resolve([]),
      ]);

      setApis(apiList);
      setApprovals(approvalList);
      setLogs(logList);
      setUsers(userList);
    } catch (err) {
      console.error("Failed to sync dashboard data:", err);
    }
  }, [currentUser]);

  // Set default view to Overview upon login
  useEffect(() => {
    if (currentUser) {
      setActiveTab("overview");
      loadData();
    }
  }, [currentUser, loadData]);

  // Poll pending approvals or requests every 8 seconds
  useEffect(() => {
    if (currentUser) {
      const pollInterval = setInterval(async () => {
        try {
          if (currentUser.role === "OPERATOR") {
            const myReqs = await api.listMyRequests();
            setApprovals(myReqs);
          } else {
            const apprs = await api.listApprovals({ status: "PENDING" });
            setApprovals(apprs);
          }
        } catch {}
      }, 8000);
      return () => clearInterval(pollInterval);
    }
  }, [currentUser]);

  const handleSignOut = async () => {
    try {
      await api.logout();
    } catch {}
    setAuthToken(null);
    setCurrentUser(null);
    setActiveTab("overview");
  };

  const pendingCount = currentUser?.role === "OPERATOR"
    ? approvals.filter((a) => a.status === "PENDING").length
    : approvals.length;

  return (
    <div className="app-container">
      {!currentUser && (
        <LoginModal onLoginSuccess={(user) => setCurrentUser(user)} />
      )}

      <Header
        activeTab={activeTab}
        setActiveTab={setActiveTab}
        pendingCount={pendingCount}
        onRefresh={loadData}
        user={currentUser}
        onSignOut={handleSignOut}
      />

      <main className="main-canvas">
        {/* Common Tab: Overview */}
        {activeTab === "overview" && (
          <Overview
            user={currentUser}
            apis={apis}
            approvals={approvals}
            logs={logs}
            users={users}
            onNavigate={(tab) => setActiveTab(tab)}
          />
        )}

        {/* Common Tab: API Tools / Registry */}
        {activeTab === "apis" && (
          <APIRegistry
            apis={apis}
            onReload={loadData}
            userRole={currentUser?.role}
          />
        )}

        {/* Operator Tab: AI Task Console */}
        {activeTab === "tasks" && currentUser?.role !== "APPROVER" && (
          <TaskConsole
            onTaskCompleted={loadData}
            onSwitchToApprovals={() => setActiveTab(currentUser?.role === "OPERATOR" ? "my_requests" : "approvals")}
            userRole={currentUser?.role}
          />
        )}

        {/* Operator Tab: My Requests */}
        {activeTab === "my_requests" && (
          <MyRequests onSwitchToConsole={() => setActiveTab("tasks")} />
        )}

        {/* Operator Tab: My Execution History */}
        {activeTab === "my_history" && (
          <AuditLogs
            logs={logs}
            onReload={loadData}
            onSwitchToApprovals={() => setActiveTab("my_requests")}
            userRole={currentUser?.role}
          />
        )}

        {/* Approver / Admin Tab: Pending Approvals */}
        {activeTab === "approvals" && currentUser?.role !== "OPERATOR" && (
          <ApprovalQueue
            approvals={approvals}
            onReload={loadData}
            userRole={currentUser?.role}
            currentUserId={currentUser?.id}
          />
        )}

        {/* Approver / Admin Tab: Approval History */}
        {activeTab === "approval_history" && currentUser?.role !== "OPERATOR" && (
          <ApprovalHistory />
        )}

        {/* Approver Tab: Relevant Execution Logs */}
        {activeTab === "relevant_logs" && currentUser?.role !== "OPERATOR" && (
          <AuditLogs
            logs={logs}
            onReload={loadData}
            onSwitchToApprovals={() => setActiveTab("approvals")}
            userRole={currentUser?.role}
          />
        )}

        {/* Admin Tab: User Management */}
        {activeTab === "users" && currentUser?.role === "ADMIN" && (
          <UserManagement />
        )}

        {/* Admin Tab: Global Execution Logs */}
        {activeTab === "logs" && currentUser?.role === "ADMIN" && (
          <AuditLogs
            logs={logs}
            onReload={loadData}
            onSwitchToApprovals={() => setActiveTab("approvals")}
            userRole={currentUser?.role}
          />
        )}

        {/* Admin Tab: System Monitoring */}
        {activeTab === "monitoring" && currentUser?.role === "ADMIN" && (
          <SystemMonitoring />
        )}

        {/* Admin Tab: Settings */}
        {activeTab === "settings" && currentUser?.role === "ADMIN" && (
          <Settings />
        )}

        {/* Common Tab: Profile */}
        {activeTab === "profile" && (
          <Profile user={currentUser} onSignOut={handleSignOut} />
        )}
      </main>
    </div>
  );
}

export default App;
