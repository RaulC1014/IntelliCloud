// src/App.jsx
import React, { useEffect, useState } from 'react';
import { isMockAuth, register, login, logout, getCurrentUser, onAuthStateChangedSub } from './firebase';
import Home from './pages/Home.jsx';
import Dashboard from './pages/Dashboard.jsx';
import Decipher from './pages/Decipher.jsx';
import logoImg from './assets/IntelliCloudLogoTransparent.png';

// --- Icons ---
const HomeIcon = () => <svg viewBox="0 0 24 24"><path d="M10 20v-6h4v6h5v-8h3L12 3 2 12h3v8z"/></svg>;
const DashboardIcon = () => <svg viewBox="0 0 24 24"><path d="M3 13h8V3H3v10zm0 8h8v-6H3v6zm10 0h8V11h-8v10zm0-18v6h8V3h-8z"/></svg>;
const DecipherIcon = () => <svg viewBox="0 0 24 24"><path d="M18 8h-1V6c0-2.76-2.24-5-5-5S7 3.24 7 6v2H6c-1.1 0-2 .9-2 2v10c0 1.1.9 2 2 2h12c1.1 0 2-.9 2-2V10c0-1.1-.9-2-2-2zm-6 9c-1.1 0-2-.9-2-2s.9-2 2-2 2 .9 2 2-.9 2-2 2zm3.1-9H8.9V6c0-1.71 1.39-3.1 3.1-3.1 1.71 0 3.1 1.39 3.1 3.1v2z"/></svg>;

// --- System Theme Hook ---
function useSystemTheme() {
  useEffect(() => {
    const mediaQuery = window.matchMedia('(prefers-color-scheme: light)');
    const applyTheme = (e) => {
      if (e.matches) document.documentElement.setAttribute('data-theme', 'light');
      else document.documentElement.removeAttribute('data-theme');
    };
    applyTheme(mediaQuery);
    mediaQuery.addEventListener('change', applyTheme);
    return () => mediaQuery.removeEventListener('change', applyTheme);
  }, []);
}

// --- Background Watermark ---
const BackgroundWatermark = () => (
  <div style={{
    position: 'absolute', top: '50%', left: '50%', transform: 'translate(-50%, -50%)',
    width: '100vw', height: '100vh',
    backgroundImage: `url(${logoImg})`, backgroundRepeat: 'no-repeat', backgroundPosition: 'center', backgroundSize: '800px',
    opacity: 'var(--logo-opacity)', zIndex: 0, pointerEvents: 'none', transition: 'opacity 0.5s ease'
  }} />
);

// --- Boot Sequence Animation ---
function BootSequence({ onComplete }) {
  const [step, setStep] = useState(0);

  useEffect(() => {
    // This timeline creates a 2.5s delay to let the database sync
    const timers = [
      setTimeout(() => setStep(1), 600),
      setTimeout(() => setStep(2), 1400),
      setTimeout(() => setStep(3), 2200),
      setTimeout(() => onComplete(), 2600)
    ];
    return () => timers.forEach(clearTimeout);
  }, [onComplete]);

  const steps = [
    "Establishing secure handshake...",
    "Verifying cryptographic keys...",
    "Synchronizing user profile...",
    "Access Granted."
  ];

  return (
    <div className="center animate-fade" style={{ flexDirection: 'column', gap: 24, zIndex: 10 }}>
      <div style={{ position: 'relative', width: 60, height: 60 }}>
        <div style={{ 
          position: 'absolute', inset: 0, border: '4px solid var(--border)', borderRadius: '50%' 
        }} />
        <div style={{ 
          position: 'absolute', inset: 0, border: '4px solid var(--brand)', borderRadius: '50%',
          borderTopColor: 'transparent', animation: 'spin 1s linear infinite' 
        }} />
      </div>
      <div className="mono" style={{ color: 'var(--brand)', fontSize: 14, minHeight: 20 }}>
        {steps[step]}
      </div>
      <style>{`@keyframes spin { 0% { transform: rotate(0deg); } 100% { transform: rotate(360deg); } }`}</style>
    </div>
  );
}

// --- Landing Page ---
function Landing({ onShowLogin, onShowRegister }) {
  const [show, setShow] = useState(false);
  useEffect(() => setShow(true), []);

  return (
    <div className={`center animate-fade ${show ? 'show' : ''}`} style={{
      display: 'flex', position: 'relative', overflow: 'hidden', minHeight: '100vh',
      flexDirection: 'column', justifyContent: 'center', alignItems: 'center', textAlign: 'center'
    }}>
      <BackgroundWatermark />
      <div className="animate-slide" style={{ position: 'relative', zIndex: 1, maxWidth: 900, padding: 20 }}>
        <div style={{
          position: 'absolute', top: 40, left: '50%', transform: 'translateX(-50%)',
          width: 200, height: 200, background: 'radial-gradient(circle, var(--brand) 0%, transparent 70%)',
          opacity: 0.25, filter: 'blur(50px)', zIndex: -1
        }} />
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 24, marginBottom: 24 }}>
          <img src={logoImg} alt="IntelliCloud Logo" style={{ width: 180, height: 'auto', filter: 'drop-shadow(0 0 25px rgba(62, 123, 255, 0.4))' }} />
          <h1 className="h1 text-alive" style={{ fontSize: 80, margin: 0, letterSpacing: '-3px', lineHeight: 1 }}>IntelliCloud</h1>
        </div>
        <p className="p-muted" style={{ fontSize: 24, margin: '0 auto 48px', maxWidth: 640, fontWeight: 400 }}>Next-Generation Threat Intelligence.</p>
        <div style={{ display: 'flex', gap: 20, justifyContent: 'center', marginBottom: 60 }}>
          <button className="btn primary" style={{ padding: '16px 48px', fontSize: 18, borderRadius: 50, boxShadow: '0 0 30px -5px rgba(62, 123, 255, 0.5)' }} onClick={onShowRegister}>Get Started</button>
          <button className="btn" style={{ padding: '16px 48px', fontSize: 18, borderRadius: 50, background: 'transparent', border: '1px solid var(--border)' }} onClick={onShowLogin}>Login</button>
        </div>
        <div style={{ width: 100, height: 4, background: 'var(--border)', margin: '0 auto 40px', borderRadius: 2 }} />
        <div style={{ maxWidth: 640, margin: '0 auto' }}>
          <p className="p-muted" style={{ fontSize: 16, lineHeight: 1.8 }}>
            <strong style={{ color: 'var(--brand)', textTransform: 'uppercase', fontSize: 12, display: 'block', marginBottom: 8, letterSpacing: 2 }}>Senior Capstone Project</strong>
            A comprehensive security platform demonstrating <span style={{color:'var(--text)'}}>Real-Time Traffic Analysis</span> and <span style={{color:'var(--text)'}}>AI-Powered Threat Detection</span>.
          </p>
        </div>
      </div>
    </div>
  );
}

// --- Auth Component (UPDATED with Boot Sequence & Clean Errors) ---
function InlineAuth({ mode, onAuthed, onBack, onSwitchMode }) {
  const [email, setEmail] = useState('');
  const [pw, setPw] = useState('');
  const [first, setFirst] = useState('');
  const [last, setLast] = useState('');
  const [dob, setDob] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  
  // State for the Boot Sequence
  const [booting, setBooting] = useState(false);
  const [authenticatedUser, setAuthenticatedUser] = useState(null);

  const isLogin = mode === 'login';

  const submit = async (e) => {
    e.preventDefault();
    setBusy(true); setError('');
    try {
      let user;
      if (isLogin) {
        user = await login(email, pw);
      } else {
        user = await register(email, pw, first.trim(), last.trim(), dob);
      }
      // Store user and START THE BOOT SEQUENCE
      setAuthenticatedUser(user);
      setBooting(true);
    } catch (err) { 
      // === CUSTOM ERROR HANDLING ===
      let msg = "An unexpected error occurred.";
      const code = err.code;

      if (code === 'auth/email-already-in-use') {
        msg = "That email is already in use. Please log in.";
      } else if (code === 'auth/invalid-credential' || code === 'auth/wrong-password' || code === 'auth/user-not-found') {
        msg = "Incorrect email or password.";
      } else if (code === 'auth/weak-password') {
        msg = "Password must be at least 6 characters.";
      } else if (code === 'auth/invalid-email') {
        msg = "Please enter a valid email address.";
      } else if (code === 'auth/too-many-requests') {
        msg = "Too many attempts. Please try again later.";
      } else {
        // Fallback: Clean up the raw message (e.g. remove "Firebase: Error (...)")
        msg = err.message ? err.message.replace('Firebase: ', '').replace('Error (', '').replace(').', '') : String(err);
      }

      setError(msg); 
      setBusy(false);
    }
  };

  // If booting, show the cool animation
  if (booting) {
    return (
      <div className="center animate-fade" style={{ position: 'relative', overflow: 'hidden', minHeight: '100vh' }}>
        <BackgroundWatermark />
        <BootSequence onComplete={() => onAuthed(authenticatedUser)} />
      </div>
    );
  }

  return (
    <div className="center animate-fade" style={{ position: 'relative', overflow: 'hidden', minHeight: '100vh' }}>
      <BackgroundWatermark />
      <div className="card animate-slide" style={{ position: 'relative', zIndex: 1, width: '100%', maxWidth: 480, padding: 40, borderRadius: 24 }}>
        <div style={{ display:'flex', justifyContent:'space-between', alignItems:'center', marginBottom:24 }}>
          <h2 className="h1" style={{ fontSize: 26, margin: 0 }}>{isLogin ? 'Welcome Back' : 'Create Account'}</h2>
          <button className="btn icon-only" onClick={onBack} style={{background:'transparent', border:'none', fontSize: 20}}>✕</button>
        </div>
        <form onSubmit={submit}>
          {!isLogin && (
            <>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16 }}>
                <div><label className="label">First name</label><input className="input" placeholder="Jane" value={first} onChange={e=>setFirst(e.target.value)} required /></div>
                <div><label className="label">Last name</label><input className="input" placeholder="Doe" value={last} onChange={e=>setLast(e.target.value)} required /></div>
              </div>
              <div style={{ marginTop: 16 }}><label className="label">Date of Birth</label><input className="input" type="date" value={dob} onChange={e=>setDob(e.target.value)} required /></div>
            </>
          )}
          <div style={{ marginTop: 16 }}><label className="label">Email</label><input className="input" type="email" placeholder="you@company.com" value={email} onChange={e=>setEmail(e.target.value)} required /></div>
          <div style={{ marginTop: 16 }}><label className="label">Password</label><input className="input" type="password" placeholder="••••••••" value={pw} onChange={e=>setPw(e.target.value)} required /></div>
          <div style={{ marginTop: 32 }}>
            <button className="btn primary" style={{ width: '100%', justifyContent: 'center', padding: 14, fontSize: 16, borderRadius: 12 }} disabled={busy}>
              {busy ? 'Processing...' : (isLogin ? 'Login' : 'Create Account')}
            </button>
          </div>
          <div style={{ marginTop: 24, textAlign: 'center', fontSize: 14, color: 'var(--muted)' }}>
            {isLogin ? (
              <span>Don't have an account? <span onClick={() => onSwitchMode('register')} className="auth-link">Create account</span></span>
            ) : (
              <span>Already have an account? <span onClick={() => onSwitchMode('login')} className="auth-link">Log in</span></span>
            )}
          </div>
          {error && <div className="badge crit" style={{ marginTop: 16, display:'flex', justifyContent:'center' }}>{error}</div>}
        </form>
      </div>
    </div>
  );
}

// --- Main App Shell ---
function AppShell({ user, onSignOut }) {
  const [tab, setTab] = useState('home');

  return (
    <div className="container animate-fade">
      <div className="header" style={{ marginBottom: 24 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 40 }}>
            <div className="brand" style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
              <img src={logoImg} alt="IC" className="logo" />
              <span className="brand-title" style={{ fontSize: 22, letterSpacing: '-0.5px' }}>IntelliCloud</span>
            </div>
            <div className="tabs">
              <button className={`tab ${tab==='home'?'active':''}`} onClick={()=>setTab('home')}>
                <HomeIcon /> <span>Home</span>
              </button>
              <button className={`tab ${tab==='dashboard'?'active':''}`} onClick={()=>setTab('dashboard')}>
                <DashboardIcon /> <span>Dashboard</span>
              </button>
              <button className={`tab ${tab==='decipher'?'active':''}`} onClick={()=>setTab('decipher')}>
                <DecipherIcon /> <span>Decipher</span>
              </button>
            </div>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
          <span className="p-muted" style={{ margin:0, fontSize: 14 }}>{user?.email}</span>
          <button className="btn" onClick={onSignOut}>Sign out</button>
        </div>
      </div>
      <div style={{ height: 10 }} />
      {tab === 'home' && <Home user={user} />}
      {tab === 'dashboard' && <Dashboard />}
      {tab === 'decipher' && <Decipher />}
    </div>
  );
}

export default function App() {
  const [mode, setMode] = useState(null); 
  const [user, setUser] = useState(() => getCurrentUser());
  useSystemTheme();

  useEffect(() => {
    // Race condition handler still here for safety
    const unsub = onAuthStateChangedSub?.((u) => {
      setUser(prev => {
        if (u && prev && u.uid === prev.uid && prev.displayName && !u.displayName) {
          return { ...u, displayName: prev.displayName };
        }
        return u;
      });
    });
    return () => { try { unsub && unsub(); } catch {} };
  }, []);

  const signOut = async () => { await logout(); setUser(null); setMode(null); };

  if (user) return <AppShell user={user} onSignOut={signOut} />;
  
  if (mode) return <InlineAuth mode={mode} onAuthed={setUser} onBack={()=>setMode(null)} onSwitchMode={setMode} />;
  
  return <Landing onShowLogin={()=>setMode('login')} onShowRegister={()=>setMode('register')} />;
}