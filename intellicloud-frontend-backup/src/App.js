/*import logo from './logo.svg';*/
import { useState, useEffect } from 'react';
import './App.css';
import LoginForm from './components/LoginForm';
import ThreatsList from './components/ThreatsList';
import AuditLog from './components/AuditLog';
import Dashboard from './components/Dashboard';

import { useAuth } from './contexts/AuthContext';
import { auth } from "./firebase";
import { onAuthStateChanged } from 'firebase/auth';

function App() {

  const [token, setToken] = useState(null);
  const { role, email } = useAuth();

  useEffect(() => {
    const unsubscribe = onAuthStateChanged(auth, async (user) => {
      if (user) {
        const token = await user.getIdToken();
        setToken(token);
        console.log("Auto-login with token: ", token);

      } else {
        setToken(null);
      }
    });

    return () => unsubscribe();
  }, []);

  const handleRefreshToken = async () => {
    const user = auth.currentUser;
    if (user) {
      try {
        const refreshedToken = await user.getIdToken(true);
        console.log("Refreshed Token:", refreshedToken);
        navigator.clipboard.writeText(refreshedToken);
        alert("Token copied to clipboard for Postman testing.");
       
      } catch (error) {
        console.error("error refreshing token:", error);
      }
    } else {
      alert("user not logged in.")
    }
  };

  if (!token) {
    return <LoginForm onLogin={setToken} />;
  }

  return (
    <div className="App p-4">
      <h1 className="text-2xl mb-6">IntelliCloud Threat Dashboard</h1>

      <p> className="mb-2"
        Logged in as <strong>{email}</strong> ({role})
      </p>

      {/*Dev only Button to Copy Token*/}
      {process.env.NODE_ENV === 'development' && (
        <button 
          onClick={handleRefreshToken} 
          className='mb-4 bg-blue-500 text-white px-4 py-2 rounded'>
          Refresh + Copy Auth Token
        </button>
      )}

      {/* Role-based dashboard UI */}
      <Dashboard />

      {/* Threat Table */}
      <ThreatsList token = {token}/>

      {/* Audit Logs */}
      <div className="mt-10">
        <AuditLog token={token} />
      </div>
    </div>
  );
}

export default App;
