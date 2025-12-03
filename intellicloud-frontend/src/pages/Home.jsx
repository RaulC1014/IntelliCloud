// src/pages/Home.jsx
import React, { useEffect, useRef, useState } from 'react';
import { USE_MOCK, API_BASE_URL } from '../config';
import logoImg from '../assets/IntelliCloudLogoTransparent.png';

// --- Icons ---
const RobotIcon = () => <svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><rect x="3" y="11" width="18" height="10" rx="2"/><circle cx="12" cy="5" r="2"/><path d="M12 7v4"/><line x1="8" y1="16" x2="8" y2="16"/><line x1="16" y1="16" x2="16" y2="16"/></svg>;
const ShieldIcon = () => <svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>;
const AlertIcon = () => <svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>;
const SearchIcon = () => <svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>;
const LockIcon = () => <svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>;

// --- Scroll Reveal Component ---
function ScrollReveal({ children, delay = 0 }) {
  const [isVisible, setIsVisible] = useState(false);
  const ref = useRef(null);
  useEffect(() => {
    const observer = new IntersectionObserver(([entry]) => {
      if (entry.isIntersecting) {
        setIsVisible(true);
        observer.disconnect();
      }
    }, { threshold: 0.15 });
    if (ref.current) observer.observe(ref.current);
    return () => observer.disconnect();
  }, []);
  return <div ref={ref} className={isVisible ? 'reveal-visible' : 'reveal-hidden'} style={{ transitionDelay: `${delay}ms` }}>{children}</div>;
}

// --- Background Watermark ---
const BackgroundWatermark = () => (
  <div style={{
    position: 'fixed', top: '50%', left: '50%', transform: 'translate(-50%, -50%)',
    width: '100vw', height: '100vh',
    backgroundImage: `url(${logoImg})`, backgroundRepeat: 'no-repeat', backgroundPosition: 'center', backgroundSize: '800px',
    opacity: 'var(--logo-opacity)', zIndex: -1, pointerEvents: 'none', transition: 'opacity 0.5s ease'
  }} />
);

export default function Home({ user }) {
  const displayName = user?.displayName || 'User';
  const firstName = displayName.split(' ')[0];

  return (
    <div className="page-home" style={{ position: 'relative', minHeight: '100vh' }}>
      <BackgroundWatermark />
      <div className="shell" style={{ maxWidth: 1200, margin: '0 auto', paddingBottom: 120 }}>
        
        {/* 1. HERO SECTION */}
        <div style={{ textAlign: 'center', marginBottom: 100, marginTop: 60 }}>
          <ScrollReveal delay={100}>
            {/* UPDATED GREETING */}
            <h1 className="h1" style={{ fontSize: 64, marginBottom: 24, lineHeight: 1.1 }}>
              Welcome, <span className="text-alive">{firstName}</span>.
            </h1>
          </ScrollReveal>
          <ScrollReveal delay={200}>
            <p className="p-muted" style={{ fontSize: 22, maxWidth: 700, margin: '0 auto', lineHeight: 1.6 }}>
              IntelliCloud isn't just a firewall. It's a <strong>living security intelligence</strong> that watches, learns, and explains threats in real-time.
            </p>
          </ScrollReveal>
        </div>

        {/* 2. THE PROBLEM VS SOLUTION (Updated Layout) */}
        <ScrollReveal delay={300}>
          <div style={{ marginBottom: 100 }}>
            {/* UPDATED GRID */}
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(400px, 1fr))', gap: 40, alignItems: 'stretch' }}>
              
              {/* The Old Way */}
              <div className="card hover-card" style={{ padding: 40, borderLeft: '4px solid var(--danger)', position: 'relative', overflow: 'hidden' }}>
                <div style={{ color: 'var(--danger)', marginBottom: 20 }}><AlertIcon /></div>
                <h3 className="h1" style={{ fontSize: 24 }}>The Old Way</h3>
                <p className="p-muted" style={{ fontSize: 16 }}>
                  Traditional security tools flood you with <strong>raw logs</strong> and cryptic error codes. 
                  Identifying a specific attack requires manual cross-referencing, SQL queries, and hours of forensic work.
                </p>
              </div>

              {/* The IntelliCloud Way */}
              <div className="card hover-card" style={{ padding: 40, borderLeft: '4px solid var(--brand)', background: 'linear-gradient(135deg, var(--panel) 0%, rgba(62, 123, 255, 0.05) 100%)', position: 'relative', overflow: 'hidden' }}>
                <div style={{ color: 'var(--brand)', marginBottom: 20 }}><ShieldIcon /></div>
                <h3 className="h1" style={{ fontSize: 24, color: 'var(--brand)' }}>The IntelliCloud Way</h3>
                <p className="p-muted" style={{ fontSize: 16 }}>
                  We ingest packets in milliseconds. Our <strong>AI Engine</strong> instantly translates hex payloads into plain English: 
                  <em>"This is a SQL Injection attempt targeting the Users table."</em> You get the <strong>Who</strong>, <strong>What</strong>, and <strong>Why</strong> instantly.
                </p>
              </div>

            </div>
          </div>
        </ScrollReveal>

        {/* 3. REAL WORLD SCENARIOS */}
        <div style={{ marginBottom: 100 }}>
          <ScrollReveal>
            <div style={{ textAlign: 'center', marginBottom: 50 }}>
              <h2 className="h1" style={{ fontSize: 36 }}>Real-World Defense</h2>
              <p className="p-muted">How we handle modern attack vectors.</p>
            </div>
          </ScrollReveal>
          
          <div className="grid-balanced" style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(320px, 1fr))', gap: 32 }}>
            <ScrollReveal delay={100}>
              <div className="card hover-card" style={{ height: '100%', padding: 32 }}>
                <div style={{ color: 'var(--warn)', marginBottom: 20 }} className="icon-glow"><SearchIcon /></div>
                <h3 style={{ fontSize: 20, marginTop: 0 }}>Command & Control</h3>
                <p className="p-muted" style={{ fontSize: 15 }}>
                  Detects when internal devices start "phoning home" to suspicious external IPs, identifying breached devices before data is stolen.
                </p>
              </div>
            </ScrollReveal>
            <ScrollReveal delay={200}>
              <div className="card hover-card" style={{ height: '100%', padding: 32 }}>
                <div style={{ color: 'var(--brand)', marginBottom: 20 }} className="icon-glow"><RobotIcon /></div>
                <h3 style={{ fontSize: 20, marginTop: 0 }}>AI-Decryption</h3>
                <p className="p-muted" style={{ fontSize: 15 }}>
                  Uses Large Language Models to analyze obfuscated shellcode and base64 strings, revealing the attacker's actual commands in plain text.
                </p>
              </div>
            </ScrollReveal>
            <ScrollReveal delay={300}>
              <div className="card hover-card" style={{ height: '100%', padding: 32 }}>
                <div style={{ color: 'var(--success)', marginBottom: 20 }} className="icon-glow"><LockIcon /></div>
                <h3 style={{ fontSize: 20, marginTop: 0 }}>Zero-Day Behavioral</h3>
                <p className="p-muted" style={{ fontSize: 15 }}>
                  Instead of relying on old signatures, we track <strong>behavioral anomalies</strong>—flagging users who suddenly access sensitive endpoints.
                </p>
              </div>
            </ScrollReveal>
          </div>
        </div>

        {/* 4. THE ENGINEERS */}
        <div style={{ marginBottom: 80 }}>
          <ScrollReveal>
            <h2 className="h1" style={{ fontSize: 36, textAlign: 'center', marginBottom: 50 }}>The Engineers</h2>
          </ScrollReveal>

          <div className="grid-halves" style={{ gap: 40 }}>
            
            {/* RAUL */}
            <ScrollReveal delay={100}>
              <div className="card hover-card" style={{ padding: 0, overflow: 'hidden', display: 'flex', flexDirection: 'column', height: '100%' }}>
                <div style={{ height: 140, background: 'linear-gradient(135deg, #064e3b 0%, #10b981 100%)', position: 'relative' }}>
                  <div style={{
                    width: 120, height: 120, borderRadius: '50%', background: 'var(--panel)', border: '4px solid var(--panel)',
                    position: 'absolute', bottom: -60, left: 32, display: 'grid', placeItems: 'center', fontSize: 50,
                    boxShadow: '0 10px 20px rgba(0,0,0,0.2)'
                  }}>
                    👨🏻‍💻
                  </div>
                </div>
                <div style={{ padding: '70px 32px 32px' }}>
                  <h2 style={{ margin: '0 0 6px', fontSize: 28 }}>Raul Cortinas</h2>
                  <div style={{ color: 'var(--brand)', fontWeight: 700, fontSize: 14, marginBottom: 20, textTransform: 'uppercase', letterSpacing: 1 }}>
                    Backend Architect & Security Lead
                  </div>
                  <p className="p-muted" style={{ fontSize: 16, lineHeight: 1.7 }}>
                    A Senior CS major with a minor in <strong>Mathematics & Cyber Security</strong>. 
                    Raul built the high-throughput ingestion pipeline and designed the threat detection logic that powers IntelliCloud's core.
                  </p>
                </div>
              </div>
            </ScrollReveal>

            {/* BRYAN */}
            <ScrollReveal delay={200}>
              <div className="card hover-card" style={{ padding: 0, overflow: 'hidden', display: 'flex', flexDirection: 'column', height: '100%' }}>
                <div style={{ height: 140, background: 'linear-gradient(135deg, #1e3a8a 0%, #3b82f6 100%)', position: 'relative' }}>
                  <div style={{
                    width: 120, height: 120, borderRadius: '50%', background: 'var(--panel)', border: '4px solid var(--panel)',
                    position: 'absolute', bottom: -60, left: 32, display: 'grid', placeItems: 'center', fontSize: 50,
                    boxShadow: '0 10px 20px rgba(0,0,0,0.2)'
                  }}>
                    👨🏼‍💻
                  </div>
                </div>
                <div style={{ padding: '70px 32px 32px' }}>
                  <h2 style={{ margin: '0 0 6px', fontSize: 28 }}>Bryan Kahl</h2>
                  <div style={{ color: 'var(--brand)', fontWeight: 700, fontSize: 14, marginBottom: 20, textTransform: 'uppercase', letterSpacing: 1 }}>
                    Frontend Lead & AI Specialist
                  </div>
                  <p className="p-muted" style={{ fontSize: 16, lineHeight: 1.7 }}>
                    Founder of <a href="https://calvia.ai" target="_blank" rel="noreferrer" className="modern-link">Calvia.ai</a>. 
                    Bryan is a Senior CS student specializing in <strong>Generative AI</strong>. He architected the frontend experience and integrated the LLM agents.
                  </p>
                </div>
              </div>
            </ScrollReveal>

          </div>
        </div>

      </div>
    </div>
  );
}