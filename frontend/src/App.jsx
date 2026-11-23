import React, { useEffect, useState } from 'react';
import Navbar from './components/Navbar';
import Dashboard from './pages/Dashboard';
import Simulation from './pages/Simulation';
import Activities from './pages/Activities';
import Login from './pages/Login';
import Research from './pages/Research';
import { logout, refreshSession, setAccessToken, setSessionExpiredHandler } from './api/client';

const PRIVILEGED = ['Admin', 'Analyst'];

export default function App() {
  // session = { username, role } once authenticated; the token itself stays in api/client.js.
  const [session, setSession] = useState(null);
  const [restoring, setRestoring] = useState(true);
  const [activeTab, setActiveTab] = useState('dashboard');

  useEffect(() => {
    setSessionExpiredHandler(() => setSession(null));
    // Try to resume a session from the httpOnly refresh cookie after a reload.
    refreshSession()
      .then((data) => setSession({ username: data.username, role: data.role }))
      .catch(() => setSession(null))
      .finally(() => setRestoring(false));
  }, []);

  const privileged = PRIVILEGED.includes(session?.role);

  useEffect(() => {
    // Standard users can only see their own telemetry.
    if (session && !privileged) setActiveTab('activities');
  }, [session, privileged]);

  const handleLoginSuccess = (data) => {
    setAccessToken(data.access_token);
    setSession({ username: data.username, role: data.role });
    setActiveTab(PRIVILEGED.includes(data.role) ? 'dashboard' : 'activities');
  };

  const handleLogout = async () => {
    try {
      await logout();
    } finally {
      setSession(null);
    }
  };

  if (restoring) {
    return <div className="min-h-screen bg-gray-950" />;
  }

  if (!session) {
    return <Login onLoginSuccess={handleLoginSuccess} />;
  }

  return (
    <div className="min-h-screen bg-gray-950 text-gray-100">
      <Navbar
        activeTab={activeTab}
        setActiveTab={setActiveTab}
        onLogout={handleLogout}
        userRole={session.role}
        privileged={privileged}
      />
      <main>
        {privileged && activeTab === 'dashboard' && <Dashboard />}
        {privileged && activeTab === 'simulation' && <Simulation />}
        {activeTab === 'activities' && <Activities privileged={privileged} />}
        {privileged && activeTab === 'research' && <Research />}
      </main>
    </div>
  );
}
