import React, { useState, useEffect, useCallback } from "react";
import { Header } from "./components/Header";
import { Overview } from "./components/Overview";
import { APIRegistry } from "./components/APIRegistry";
import { NewRequest } from "./components/NewRequest";
import { RequestHistory } from "./components/RequestHistory";
import { ApprovalQueue } from "./components/ApprovalQueue";
import { ApprovalHistory } from "./components/ApprovalHistory";
import { MyRequests } from "./components/MyRequests";
import { AuditLogs } from "./components/AuditLogs";
import { UserManagement } from "./components/UserManagement";
import { RoleManagement } from "./components/RoleManagement";
import { SecurityPolicies } from "./components/SecurityPolicies";
import { SystemMonitoring } from "./components/SystemMonitoring";
import { Settings } from "./components/Settings";
import { Profile } from "./components/Profile";
import LoginModal from "./components/LoginModal";
import { api, setAuthToken, setOnUnauthorized } from "./services/api";

export function App() {
  const [currentUser, setCurrentUser] = useState(null);
  const [activeTab, setActiveTab] = useState("overview");
  const [switchingRole, setSwitchingRole] = useState(null);
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

      const [apiList, approvalList, logList, userList] = await Promise.all([
        // OPERATOR does not access full API Registry (/apis is 403 for OPERATOR)
        isAdmin ? api.listApis().catch(() => []) : Promise.resolve([]),
        isOperator
          ? api.listMyRequests().catch(() => [])
          : api.listApprovals({ status: "PENDING" }).catch(() => []),
        // Backend strictly scopes /logs by role and demo isolation
        api.listLogs().catch(() => []),
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

  // Reset to Overview upon login or role switch
  useEffect(() => {
    if (currentUser) {
      setActiveTab("overview");
      loadData();
    }
  }, [currentUser, loadData]);

  // Poll pending approvals or own requests every 8 seconds
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

  const clearSessionState = () => {
    setAuthToken(null);
    setCurrentUser(null);
    setApis([]);
    setApprovals([]);
    setLogs([]);
    setUsers([]);
    setActiveTab("overview");
  };

  const handleSignOut = async () => {
    try {
      await api.logout();
    } catch {}
    clearSessionState();
  };

  const handleSwitchDemoRole = async (targetRoleKey) => {
    if (switchingRole) return;
    setSwitchingRole(targetRoleKey);
    try {
      // Clear all prior role view state before switching
      setApis([]);
      setApprovals([]);
      setLogs([]);
      setUsers([]);

      // Atomically revokes previous role JWT server-side and issues a new token in the SAME isolated demo_session_id
      const data = await api.demoSwitchRole(targetRoleKey);
      setAuthToken(data.access_token);
      setActiveTab("overview");
      setCurrentUser({
        id: data.user_id,
        username: data.username,
        role: data.role,
        is_demo: Boolean(data.is_demo),
        demo_session_id: data.demo_session_id || null,
        token: data.access_token,
      });
    } catch (err) {
      console.error("Failed to switch demo role:", err);
      clearSessionState();
    } finally {
      setSwitchingRole(null);
    }
  };

  const isDemo = Boolean(currentUser?.is_demo);

  const pendingCount =
    currentUser?.role === "OPERATOR"
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
        onSwitchDemoRole={handleSwitchDemoRole}
        switchingRole={switchingRole}
      />

      <main className="main-canvas">
        {/* Common: Role-Specific Overview */}
        {currentUser && activeTab === "overview" && (
          <Overview
            user={currentUser}
            apis={apis}
            approvals={approvals}
            logs={logs}
            users={users}
            onNavigate={(tab) => setActiveTab(tab)}
          />
        )}

        {/* ================= USER (OPERATOR) ROUTES ================= */}
        {currentUser?.role === "OPERATOR" && activeTab === "new_request" && (
          <NewRequest
            isDemo={isDemo}
            onRequestSubmitted={loadData}
            onViewMyRequests={() => setActiveTab("my_requests")}
            onViewHistory={() => setActiveTab("request_history")}
          />
        )}

        {currentUser?.role === "OPERATOR" && activeTab === "my_requests" && (
          <MyRequests onNewRequest={() => setActiveTab("new_request")} />
        )}

        {currentUser?.role === "OPERATOR" && activeTab === "request_history" && (
          <RequestHistory
            logs={logs}
            onReload={loadData}
            onNewRequest={() => setActiveTab("new_request")}
          />
        )}

        {/* ================= APPROVER ROUTES ================= */}
        {currentUser?.role === "APPROVER" && activeTab === "approvals" && (
          <ApprovalQueue
            approvals={approvals}
            onReload={loadData}
            userRole={currentUser.role}
            currentUserId={currentUser.id}
          />
        )}

        {currentUser?.role === "APPROVER" && activeTab === "approval_history" && (
          <ApprovalHistory />
        )}

        {currentUser?.role === "APPROVER" && activeTab === "request_logs" && (
          <AuditLogs
            logs={logs}
            onReload={loadData}
            onSwitchToApprovals={() => setActiveTab("approvals")}
            userRole={currentUser.role}
            isDemo={isDemo}
          />
        )}

        {/* ================= ADMIN ROUTES ================= */}
        {currentUser?.role === "ADMIN" && activeTab === "apis" && (
          <APIRegistry
            apis={apis}
            onReload={loadData}
            userRole={currentUser.role}
            isDemo={isDemo}
          />
        )}

        {currentUser?.role === "ADMIN" && activeTab === "users" && (
          <UserManagement onUsersChanged={loadData} isDemo={isDemo} />
        )}

        {currentUser?.role === "ADMIN" && activeTab === "roles" && (
          <RoleManagement currentUserId={currentUser.id} onUpdated={loadData} isDemo={isDemo} />
        )}

        {currentUser?.role === "ADMIN" && activeTab === "logs" && (
          <AuditLogs
            logs={logs}
            onReload={loadData}
            onSwitchToApprovals={() => setActiveTab("overview")}
            userRole={currentUser.role}
            isDemo={isDemo}
          />
        )}

        {currentUser?.role === "ADMIN" && activeTab === "security" && (
          <SecurityPolicies />
        )}

        {currentUser?.role === "ADMIN" && activeTab === "monitoring" && (
          <SystemMonitoring />
        )}

        {currentUser?.role === "ADMIN" && activeTab === "settings" && (
          <Settings />
        )}

        {/* ================= PROFILE (USER & APPROVER) ================= */}
        {currentUser && activeTab === "profile" && (
          <Profile user={currentUser} onSignOut={handleSignOut} />
        )}
      </main>
    </div>
  );
}

export default App;
