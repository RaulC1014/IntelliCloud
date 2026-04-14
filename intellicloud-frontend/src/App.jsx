import React, { useEffect, useMemo, useState, useCallback } from "react";
import {
  register,
  login,
  logout,
  getCurrentUser,
  onAuthStateChangedSub,
} from "./firebase";

import Home from "./pages/Home.jsx";
import Dashboard from "./pages/Dashboard.jsx";
import Decipher from "./pages/Decipher.jsx";
import Devices from "./pages/Devices.jsx";
import LogAnalyzer from "./pages/LogAnalyzer.jsx";
import PcapParser from "./pages/PcapParser.jsx";
import Cases from "./pages/Cases.jsx";
import Tools from "./pages/Tools.jsx";

import logoImg from "./assets/IntellicloudLogoTransparent.png";

const IDLE_LOGOUT_MS = 15 * 60 * 1000;

const HomeIcon = () => (
  <svg viewBox="0 0 24 24" aria-hidden="true">
    <path d="M10 20v-6h4v6h5v-8h3L12 3 2 12h3v8z" />
  </svg>
);

const DashboardIcon = () => (
  <svg viewBox="0 0 24 24" aria-hidden="true">
    <path d="M3 13h8V3H3v10zm0 8h8v-6H3v6zm10 0h8V11h-8v10zm0-18v6h8V3h-8z" />
  </svg>
);

const DecipherIcon = () => (
  <svg viewBox="0 0 24 24" aria-hidden="true">
    <path d="M18 8h-1V6c0-2.76-2.24-5-5-5S7 3.24 7 6v2H6c-1.1 0-2 .9-2 2v10c0 1.1.9 2 2 2h12c1.1 0 2-.9 2-2V10c0-1.1-.9-2-2-2zm-6 9c-1.1 0-2-.9-2-2s.9-2 2-2 2 .9 2 2-.9 2-2 2zm3.1-9H8.9V6c0-1.71 1.39-3.1 3.1-3.1 1.71 0 3.1 1.39 3.1 3.1v2z" />
  </svg>
);

const DevicesIcon = () => (
  <svg viewBox="0 0 24 24" aria-hidden="true">
    <path d="M4 6h16a2 2 0 0 1 2 2v7a2 2 0 0 1-2 2h-6v2h2a1 1 0 1 1 0 2H8a1 1 0 1 1 0-2h2v-2H4a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2zm0 2v7h16V8H4zm3 3a1 1 0 1 0 0 .001V11zm3 0a1 1 0 1 0 0 .001V11z" />
  </svg>
);

const LogAnalyzerIcon = () => (
  <svg viewBox="0 0 24 24" aria-hidden="true">
    <path d="M6 2h9l5 5v13a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2zm8 1.5V8h4.5L14 3.5zM8 11h8a1 1 0 0 0 0-2H8a1 1 0 0 0 0 2zm0 4h8a1 1 0 0 0 0-2H8a1 1 0 0 0 0 2zm0 4h5a1 1 0 0 0 0-2H8a1 1 0 0 0 0 2z" />
  </svg>
);

const PcapParserIcon = () => (
  <svg viewBox="0 0 24 24" aria-hidden="true">
    <path d="M4 5h16a2 2 0 0 1 2 2v4h-2V7H4v10h7v2H4a2 2 0 0 1-2-2V7a2 2 0 0 1 2-2zm12 7 6 3.5-6 3.5V16h-5v-1h5v-3z" />
  </svg>
);

const CasesIcon = () => (
  <svg viewBox="0 0 24 24" aria-hidden="true">
    <path d="M20 7H4a2 2 0 0 0-2 2v10a2 2 0 0 0 2 2h16a2 2 0 0 0 2-2V9a2 2 0 0 0-2-2zm-9 8H7v-2h4v2zm6-4H7v-2h10v2z"/>
  </svg>
);

const ToolsIcon = () => (
  <svg viewBox="0 0 24 24" aria-hidden="true">
    <path d="M22.7 19l-9.1-9.1c.9-2.3.4-5-1.5-6.9-2-2-5-2.4-7.4-1.3L9 6 6 9 1.6 4.7C.4 7.1.9 10.1 2.9 12.1c1.9 1.9 4.6 2.4 6.9 1.5l9.1 9.1c.4.4 1 .4 1.4 0l2.3-2.3c.5-.4.5-1.1.1-1.4z"/>
  </svg>
);

function useSystemTheme() {
  useEffect(() => {
    const mediaQuery = window.matchMedia("(prefers-color-scheme: light)");

    const applyTheme = (e) => {
      if (e.matches) {
        document.documentElement.setAttribute("data-theme", "light");
      } else {
        document.documentElement.removeAttribute("data-theme");
      }
    };

    applyTheme(mediaQuery);
    mediaQuery.addEventListener("change", applyTheme);

    return () => mediaQuery.removeEventListener("change", applyTheme);
  }, []);
}

function BackgroundWatermark() {
  return (
    <div
      style={{
        position: "absolute",
        top: "50%",
        left: "50%",
        transform: "translate(-50%, -50%)",
        width: "100vw",
        height: "100vh",
        backgroundImage: `url(${logoImg})`,
        backgroundRepeat: "no-repeat",
        backgroundPosition: "center",
        backgroundSize: "800px",
        opacity: "var(--logo-opacity)",
        zIndex: 0,
        pointerEvents: "none",
        transition: "opacity 0.5s ease",
      }}
    />
  );
}

function BootSequence({ onComplete }) {
  const [step, setStep] = useState(0);

  useEffect(() => {
    const timers = [
      setTimeout(() => setStep(1), 600),
      setTimeout(() => setStep(2), 1400),
      setTimeout(() => setStep(3), 2200),
      setTimeout(() => onComplete(), 2600),
    ];

    return () => timers.forEach(clearTimeout);
  }, [onComplete]);

  const steps = [
    "Establishing secure handshake...",
    "Verifying cryptographic keys...",
    "Synchronizing user profile...",
    "Access Granted.",
  ];

  return (
    <div
      className="center animate-fade"
      style={{ flexDirection: "column", gap: 24, zIndex: 10 }}
    >
      <div style={{ position: "relative", width: 60, height: 60 }}>
        <div
          style={{
            position: "absolute",
            inset: 0,
            border: "4px solid var(--border)",
            borderRadius: "50%",
          }}
        />
        <div
          style={{
            position: "absolute",
            inset: 0,
            border: "4px solid var(--brand)",
            borderRadius: "50%",
            borderTopColor: "transparent",
            animation: "spin 1s linear infinite",
          }}
        />
      </div>

      <div className="mono" style={{ color: "var(--brand)", fontSize: 14, minHeight: 20 }}>
        {steps[step]}
      </div>

      <style>{`
        @keyframes spin {
          0% { transform: rotate(0deg); }
          100% { transform: rotate(360deg); }
        }
      `}</style>
    </div>
  );
}

function Landing({ onShowLogin, onShowRegister }) {
  const [show, setShow] = useState(false);

  useEffect(() => setShow(true), []);

  return (
    <div
      className={`center animate-fade ${show ? "show" : ""}`}
      style={{
        display: "flex",
        position: "relative",
        overflow: "hidden",
        minHeight: "100vh",
        flexDirection: "column",
        justifyContent: "center",
        alignItems: "center",
        textAlign: "center",
      }}
    >
      <BackgroundWatermark />

      <div
        className="animate-slide"
        style={{ position: "relative", zIndex: 1, maxWidth: 900, padding: 20 }}
      >
        <div
          style={{
            position: "absolute",
            top: 40,
            left: "50%",
            transform: "translateX(-50%)",
            width: 200,
            height: 200,
            background: "radial-gradient(circle, var(--brand) 0%, transparent 70%)",
            opacity: 0.25,
            filter: "blur(50px)",
            zIndex: -1,
          }}
        />

        <div
          style={{
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
            gap: 24,
            marginBottom: 24,
          }}
        >
          <img
            src={logoImg}
            alt="IntelliCloud Logo"
            style={{
              width: 180,
              height: "auto",
              filter: "drop-shadow(0 0 25px rgba(62, 123, 255, 0.4))",
            }}
          />

          <h1
            className="h1 text-alive"
            style={{
              fontSize: 80,
              margin: 0,
              letterSpacing: "-2px",
              lineHeight: 1,
              fontWeight: 900,
              fontFamily:
                '"DM Sans", system-ui, -apple-system, Segoe UI, Roboto, Helvetica, Arial, sans-serif',
            }}
          >
            IntelliCloud
          </h1>
        </div>

        <p
          className="p-muted"
          style={{
            fontSize: 24,
            margin: "0 auto 48px",
            maxWidth: 640,
            fontWeight: 400,
          }}
        >
          Next-Generation Threat Intelligence.
        </p>

        <div
          style={{
            display: "flex",
            gap: 20,
            justifyContent: "center",
            marginBottom: 14,
          }}
        >
          <button
            className="btn primary"
            style={{
              padding: "16px 48px",
              fontSize: 18,
              borderRadius: 50,
              boxShadow: "0 0 30px -5px rgba(62, 123, 255, 0.5)",
            }}
            onClick={onShowRegister}
          >
            Get Started
          </button>

          <button
            className="btn"
            style={{
              padding: "16px 48px",
              fontSize: 18,
              borderRadius: 50,
              background: "transparent",
              border: "1px solid var(--border)",
            }}
            onClick={onShowLogin}
          >
            Login
          </button>
        </div>

        <p
          className="p-muted"
          style={{
            margin: "60px auto 0",
            fontSize: 14,
            letterSpacing: "0.2px",
            opacity: 0.85,
            maxWidth: 640,
          }}
        >
          A senior capstone project by Raul Cortinas and Bryan Kahl
        </p>
      </div>
    </div>
  );
}

function InlineAuth({ mode, onAuthed, onBack, onSwitchMode }) {
  const isLogin = mode === "login";

  const [email, setEmail] = useState("");
  const [pw, setPw] = useState("");
  const [first, setFirst] = useState("");
  const [last, setLast] = useState("");
  const [dob, setDob] = useState("");

  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [booting, setBooting] = useState(false);
  const [authenticatedUser, setAuthenticatedUser] = useState(null);

  const submit = async (e) => {
    e.preventDefault();
    setBusy(true);
    setError("");

    try {
      const user = isLogin
        ? await login(email, pw)
        : await register(email, pw, first.trim(), last.trim(), dob);

      setAuthenticatedUser(user);
      setBooting(true);
    } catch (err) {
      let msg = "An unexpected error occurred.";
      const code = err?.code;

      if (code === "auth/email-already-in-use") {
        msg = "That email is already in use. Please log in.";
      } else if (
        code === "auth/invalid-credential" ||
        code === "auth/wrong-password" ||
        code === "auth/user-not-found"
      ) {
        msg = "Incorrect email or password.";
      } else if (code === "auth/weak-password") {
        msg = "Password must be at least 6 characters.";
      } else if (code === "auth/invalid-email") {
        msg = "Please enter a valid email address.";
      } else if (code === "auth/too-many-requests") {
        msg = "Too many attempts. Please try again later.";
      } else {
        msg = err?.message
          ? err.message
              .replace("Firebase: ", "")
              .replace("Error (", "")
              .replace(").", "")
          : String(err);
      }

      setError(msg);
      setBusy(false);
    }
  };

  if (booting) {
    return (
      <div
        className="center animate-fade"
        style={{ position: "relative", overflow: "hidden", minHeight: "100vh" }}
      >
        <BackgroundWatermark />
        <BootSequence onComplete={() => onAuthed(authenticatedUser)} />
      </div>
    );
  }

  return (
    <div
      className="center animate-fade"
      style={{ position: "relative", overflow: "hidden", minHeight: "100vh" }}
    >
      <BackgroundWatermark />

      <div
        className="card animate-slide"
        style={{
          position: "relative",
          zIndex: 1,
          width: "100%",
          maxWidth: 480,
          padding: 40,
          borderRadius: 24,
        }}
      >
        <div
          style={{
            display: "flex",
            justifyContent: "space-between",
            alignItems: "center",
            marginBottom: 24,
          }}
        >
          <h2 className="h1" style={{ fontSize: 26, margin: 0 }}>
            {isLogin ? "Welcome Back" : "Create Account"}
          </h2>

          <button
            className="btn icon-only"
            onClick={onBack}
            style={{ background: "transparent", border: "none", fontSize: 20 }}
            aria-label="Close authentication form"
          >
            ✕
          </button>
        </div>

        <form onSubmit={submit}>
          {!isLogin && (
            <>
              <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 16 }}>
                <div>
                  <label className="label">First name</label>
                  <input
                    className="input"
                    placeholder="Jane"
                    value={first}
                    onChange={(e) => setFirst(e.target.value)}
                    required
                    autoComplete="given-name"
                  />
                </div>

                <div>
                  <label className="label">Last name</label>
                  <input
                    className="input"
                    placeholder="Doe"
                    value={last}
                    onChange={(e) => setLast(e.target.value)}
                    required
                    autoComplete="family-name"
                  />
                </div>
              </div>

              <div style={{ marginTop: 16 }}>
                <label className="label">Date of Birth</label>
                <input
                  className="input"
                  type="date"
                  value={dob}
                  onChange={(e) => setDob(e.target.value)}
                  required
                />
              </div>
            </>
          )}

          <div style={{ marginTop: 16 }}>
            <label className="label">Email</label>
            <input
              className="input"
              type="email"
              placeholder="you@company.com"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              required
              autoComplete="email"
              spellCheck={false}
            />
          </div>

          <div style={{ marginTop: 16 }}>
            <label className="label">Password</label>
            <input
              className="input"
              type="password"
              placeholder="••••••••"
              value={pw}
              onChange={(e) => setPw(e.target.value)}
              required
              autoComplete={isLogin ? "current-password" : "new-password"}
            />
          </div>

          <div style={{ marginTop: 32 }}>
            <button
              className="btn primary"
              style={{
                width: "100%",
                justifyContent: "center",
                padding: 14,
                fontSize: 16,
                borderRadius: 12,
              }}
              disabled={busy}
            >
              {busy ? "Processing..." : isLogin ? "Login" : "Create Account"}
            </button>
          </div>

          <div
            style={{
              marginTop: 24,
              textAlign: "center",
              fontSize: 14,
              color: "var(--muted)",
            }}
          >
            {isLogin ? (
              <span>
                Don&apos;t have an account?{" "}
                <span onClick={() => onSwitchMode("register")} className="auth-link">
                  Create account
                </span>
              </span>
            ) : (
              <span>
                Already have an account?{" "}
                <span onClick={() => onSwitchMode("login")} className="auth-link">
                  Log in
                </span>
              </span>
            )}
          </div>

          {error && (
            <div
              className="badge crit"
              style={{ marginTop: 16, display: "flex", justifyContent: "center" }}
            >
              {error}
            </div>
          )}
        </form>
      </div>
    </div>
  );
}

function AppShell({ user, onSignOut }) {
  const [tab, setTab] = useState("home");

  const tabs = useMemo(
    () => [
      { id: "home", label: "Home", Icon: HomeIcon },
      { id: "dashboard", label: "Dashboard", Icon: DashboardIcon },
      { id: "cases",        label: "Cases",         Icon: CasesIcon },
      { id: "decipher", label: "Decipher", Icon: DecipherIcon },
      { id: "devices", label: "Devices", Icon: DevicesIcon },
      { id: "log-analyzer", label: "Log Analyzer", Icon: LogAnalyzerIcon },
      { id: "pcapparser", label: "PCAP Parser", Icon: PcapParserIcon },
      { id: "tools",        label: "Tools",         Icon: ToolsIcon },
    ],
    []
  );

  const renderTab = () => {
    switch (tab) {
      case "home":
        return <Home user={user} />;
      case "dashboard":
        return <Dashboard />;
      case "decipher":
        return <Decipher />;
      case "devices":
        return <Devices />;
      case "log-analyzer":
        return <LogAnalyzer />;
      case "pcapparser":
        return <PcapParser/>
      case "cases":
        return <Cases />;
      case "tools":
        return <Tools />;
      default:
        return <Home user={user} />;
    }
  };

  return (
    <div className="container animate-fade">
      <div className="header" style={{ marginBottom: 24 }}>
        <div style={{ display: "flex", alignItems: "center", gap: 40 }}>
          <div className="brand" style={{ display: "flex", alignItems: "center", gap: 12 }}>
            <img src={logoImg} alt="IC" className="logo" />
            <span className="brand-title" style={{ fontSize: 22, letterSpacing: "-0.5px" }}>
              IntelliCloud
            </span>
          </div>

          <div className="tabs">
                        {tabs.map(({ id, label, Icon }) => (
                <button
                  key={id}
                  className={`tab ${tab === id ? "active" : ""}`}
                  onClick={() => setTab(id)}
                  aria-current={tab === id ? "page" : undefined}
                >
                  {Icon ? <Icon /> : null}
                  <span>{label}</span>
                </button>
              ))}
          </div>
        </div>

        <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
          <span className="p-muted" style={{ margin: 0, fontSize: 14 }}>
            {user?.displayName ? `Welcome, ${user.displayName}` : user?.email}
          </span>

          <button className="btn" onClick={onSignOut}>
            Sign out
          </button>
        </div>
      </div>

      <div style={{ height: 10 }} />
      {renderTab()}
    </div>
  );
}

export default function App() {
  const [mode, setMode] = useState(null);
  const [user, setUser] = useState(() => getCurrentUser());

  useSystemTheme();

  useEffect(() => {
    const unsub = onAuthStateChangedSub?.((u) => {
      setUser((prev) => {
        if (u && prev && u.uid === prev.uid && prev.displayName && !u.displayName) {
          return { ...u, displayName: prev.displayName };
        }
        return u;
      });
    });

    return () => {
      if (typeof unsub === "function") {
        try {
          unsub();
        } catch (err) {
          console.error("Failed to unsubscribe from auth state changes:", err);
        }
      }
    };
  }, []);

  useEffect(() => {
    if (!user) return undefined;

    let timeoutId;

    const resetIdleTimer = () => {
      window.clearTimeout(timeoutId);
      timeoutId = window.setTimeout(async () => {
        try {
          await logout();
        } catch (err) {
          console.error("Auto sign-out failed:", err);
        } finally {
          setUser(null);
          setMode(null);
        }
      }, IDLE_LOGOUT_MS);
    };

    const events = ["mousemove", "keydown", "click", "scroll", "touchstart"];

    events.forEach((eventName) => {
      window.addEventListener(eventName, resetIdleTimer, { passive: true });
    });

    resetIdleTimer();

    return () => {
      window.clearTimeout(timeoutId);
      events.forEach((eventName) => {
        window.removeEventListener(eventName, resetIdleTimer);
      });
    };
  }, [user]);

  const signOut = useCallback(async () => {
    await logout();
    setUser(null);
    setMode(null);
  }, []);

  if (user) {
    return <AppShell user={user} onSignOut={signOut} />;
  }

  if (mode) {
    return (
      <InlineAuth
        mode={mode}
        onAuthed={setUser}
        onBack={() => setMode(null)}
        onSwitchMode={setMode}
      />
    );
  }

  return (
    <Landing
      onShowLogin={() => setMode("login")}
      onShowRegister={() => setMode("register")}
    />
  );
}