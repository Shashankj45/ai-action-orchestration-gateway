import React, { useState, useEffect, useCallback } from "react";
import { Header } from "./components/Header";
import { APIRegistry } from "./components/APIRegistry";
import { TaskConsole } from "./components/TaskConsole";
import { ApprovalQueue } from "./components/ApprovalQueue";
import { AuditLogs } from "./components/AuditLogs";
import LoginModal from "./components/LoginModal";
import { api, setAuthToken, setOnUnauthorized } from "./services/api";

export function App() {
  const [currentUser, setCurrentUser] = useState(null);
  const [activeTab, setActiveTab] = useState("apis");
  const [apis, setApis] = useState([]);
  const [approvals, setApprovals] = useState([]);
  const [logs, setLogs] = useState([]);

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
      const [apiList, approvalList, logList] = await Promise.all([
        api.listApis().catch(() => []),
        currentUser.role !== "OPERATOR" ? api.listApprovals().catch(() => []) : Promise.resolve([]),
        api.listLogs().catch(() => []),
      ]);
      setApis(apiList);
      setApprovals(approvalList);
      setLogs(logList);
    } catch (err) {
      console.error("Failed to sync dashboard data:", err);
    }
  }, [currentUser]);

  useEffect(() => {
    if (currentUser) {
      loadData();
      // Poll pending approvals every 8 seconds for live state updates
      const pollInterval = setInterval(async () => {
        if (currentUser.role !== "OPERATOR") {
          try {
            const apprs = await api.listApprovals();
            setApprovals(apprs);
          } catch {}
        }
      }, 8000);
      return () => clearInterval(pollInterval);
    }
  }, [currentUser, loadData]);

  const handleSignOut = async () => {
    try {
      await api.logout();
    } catch {
      // Proceed with local cleanup regardless of network errors
    }
    setAuthToken(null);
    setCurrentUser(null);
  };

  return (
    <div className="app-container">
      {!currentUser && (
        <LoginModal onLoginSuccess={(user) => setCurrentUser(user)} />
      )}

      <Header
        activeTab={activeTab}
        setActiveTab={setActiveTab}
        pendingCount={approvals.length}
        onRefresh={loadData}
        user={currentUser}
        onSignOut={handleSignOut}
      />

      <main className="main-canvas">
        {activeTab === "apis" && (
          <APIRegistry
            apis={apis}
            onReload={loadData}
            userRole={currentUser?.role}
          />
        )}

        {activeTab === "tasks" && (
          <TaskConsole
            onTaskCompleted={loadData}
            onSwitchToApprovals={() => setActiveTab("approvals")}
            userRole={currentUser?.role}
          />
        )}

        {activeTab === "approvals" && (
          <ApprovalQueue
            approvals={approvals}
            onReload={loadData}
            userRole={currentUser?.role}
            currentUserId={currentUser?.id}
          />
        )}

        {activeTab === "logs" && (
          <AuditLogs
            logs={logs}
            onReload={loadData}
            onSwitchToApprovals={() => setActiveTab("approvals")}
            userRole={currentUser?.role}
          />
        )}
      </main>
    </div>
  );
}

export default App;
