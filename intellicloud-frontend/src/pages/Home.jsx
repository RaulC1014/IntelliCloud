import React, { useState, useRef, useEffect } from "react";

// --- The 7 Core Features of IntelliCloud ---
const FEATURES = [
  {
    id: "dashboard",
    label: "Dashboard",
    tagline: "Your Real-Time Command Center",
    desc: "Get a high-level, instantaneous overview of network health, active alerts, and recent ingest metrics. Instantly visualize your threat landscape at a single glance."
  },
  {
    id: "cases",
    label: "Cases",
    tagline: "Streamlined Incident Response",
    desc: "Manage and track active security incidents. Group related alerts together, assign investigations, store critical evidence, and maintain a chronological timeline of mitigation."
  },
  {
    id: "decipher",
    label: "Decipher",
    tagline: "AI-Powered Payload Analysis",
    desc: "Unmask the unknown. Feed obfuscated scripts, suspicious code, or complex payloads to our AI engine for instant deobfuscation, translation, and threat assessment."
  },
  {
    id: "devices",
    label: "Devices",
    tagline: "Complete Asset Visibility",
    desc: "Maintain a comprehensive inventory of your network. Monitor connected nodes, identify vulnerable endpoints, and track rogue devices attempting to breach your perimeter."
  },
  {
    id: "log-analyzer",
    label: "Log Analyzer",
    tagline: "Advanced Anomaly Detection",
    desc: "Ingest, parse, and query massive volumes of system logs. Sift through thousands of events in seconds to pinpoint operational anomalies and trace attacker footprints."
  },
  {
    id: "pcapparser",
    label: "PCAP Parser",
    tagline: "Deep Packet Inspection",
    desc: "Perform forensic network analysis. Upload raw PCAP files to reconstruct traffic flows, extract transferred files, and uncover hidden, malicious network communications."
  },
  {
    id: "tools",
    label: "Tools",
    tagline: "The Threat Hunter's Utility Belt",
    desc: "A specialized toolkit granting rapid access to IP reputation lookups, geolocation tracking, hash verification, and swift OSINT capabilities."
  }
];

// --- The Interactive Sliding Component ---
export function FeatureShowcase({ setTab }) {
  const [activeId, setActiveId] = useState(FEATURES[0].id);
  const activeFeature = FEATURES.find(f => f.id === activeId);

  return (
    <div className="showcase-container animate-slide" style={{ marginTop: '0px' }}>
      
      {/* Centered, wrapped tab grid without arrows */}
      <div style={{ display: 'flex', justifyContent: 'center', marginBottom: '32px' }}>
        <div className="showcase-tabs-grid">
          {FEATURES.map((feature) => (
            <button
              key={feature.id}
              className={`showcase-tab ${activeId === feature.id ? "active" : ""}`}
              onClick={() => setActiveId(feature.id)}
            >
              {feature.label}
            </button>
          ))}
        </div>
      </div>

      <div className="showcase-content-card glass-panel hover-card" key={activeId}>
        <div className="showcase-text-content">
          
          <h3 className="h1" style={{ fontSize: 32, margin: "0 0 8px 0", letterSpacing: "-0.5px", background: "none", color: "#fff", WebkitTextFillColor: "#fff" }}>
            {activeFeature.label}
          </h3>
          
          <h4 className="gradient-text" style={{ margin: "0 0 20px 0", fontWeight: 600, fontSize: 18 }}>
            {activeFeature.tagline}
          </h4>
          
          <p style={{ color: "rgba(255, 255, 255, 0.6)", fontSize: 16, lineHeight: 1.6, margin: 0, maxWidth: "90%" }}>
            {activeFeature.desc}
          </p>

          <button
            className="btn-glass"
            style={{ marginTop: 32 }}
            onClick={() => setTab(activeFeature.id)}
          >
            Launch {activeFeature.label}
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round"><path d="M5 12h14M12 5l7 7-7 7"/></svg>
          </button>
        </div>
      </div>
    </div>
  );
}

// --- Smooth Fade In ---
export function FadeIn({ children, delay = 0 }) {
  const [isVisible, setIsVisible] = useState(false);
  const ref = useRef(null);
  useEffect(() => {
    const observer = new IntersectionObserver(([entry]) => {
      if (entry.isIntersecting) {
        setIsVisible(true);
        observer.disconnect();
      }
    }, { threshold: 0.1 });
    if (ref.current) observer.observe(ref.current);
    return () => observer.disconnect();
  }, []);
  
  return (
    <div ref={ref} style={{
      opacity: isVisible ? 1 : 0,
      transform: isVisible ? 'translateY(0)' : 'translateY(30px)',
      transition: `all 0.8s cubic-bezier(0.16, 1, 0.3, 1) ${delay}ms`
    }}>
      {children}
    </div>
  );
}

// --- Main Home Component ---
export default function Home({ user, setTab }) {
  const displayName = user?.displayName || 'User';
  const firstName = displayName.split(' ')[0];

  return (
    <div style={{ fontFamily: '"Inter", -apple-system, sans-serif' }}>
      <div style={{ maxWidth: 1000, margin: '0 auto', padding: '80px 24px 80px' }}>
        
        {/* 1. HERO SECTION */}
        <div style={{ textAlign: 'center', marginBottom: 80 }}>
          <FadeIn>
            <div style={{ 
              display: 'inline-block', 
              padding: '8px 16px', 
              borderRadius: '30px', 
              backgroundColor: 'rgba(255,255,255,0.05)', 
              border: '1px solid rgba(255,255,255,0.1)',
              fontSize: '14px',
              color: 'rgba(255,255,255,0.8)',
              marginBottom: '32px'
            }}>
              Welcome back, {firstName}.
            </div>
          </FadeIn>

          <FadeIn delay={100}>
            <h1 className="gradient-text" style={{ 
              fontSize: 'clamp(48px, 6vw, 72px)', 
              fontWeight: 600, 
              letterSpacing: '-0.03em', 
              lineHeight: 1.1, 
              margin: '0 0 24px 0' 
            }}>
              The Swiss Army Knife of<br/>Cyber Security
            </h1>
          </FadeIn>

          <FadeIn delay={200}>
            <p style={{ 
              fontSize: '20px', 
              color: 'rgba(255,255,255,0.6)', 
              lineHeight: 1.6, 
              maxWidth: '640px', 
              margin: '0 auto' 
            }}>
              Complex security, made ridiculously simple. We watch your network, catch threats, and explain exactly what's happening in plain English.
            </p>
          </FadeIn>
        </div>

        {/* 2. THE INFO VIEWER */}
        <FadeIn delay={300}>
          <div style={{ textAlign: 'center', marginTop: '80px', marginBottom: '20px' }}>
            <h2 style={{ fontSize: '20px', fontWeight: 500, color: 'rgba(255,255,255,0.8)' }}>How IntelliCloud Works</h2>
          </div>
          
          <FeatureShowcase setTab={setTab} />
        </FadeIn>

        {/* 3. THE TEAM */}
        <div style={{ marginTop: '140px' }}>
          <FadeIn>
            <h2 style={{ fontSize: '32px', fontWeight: 600, textAlign: 'center', marginBottom: '60px', color: '#fff' }}>
              Meet the Builders
            </h2>
          </FadeIn>

          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(300px, 1fr))', gap: '32px' }}>
            
            {/* Raul */}
            <FadeIn delay={100}>
              <div className="glass-panel" style={{ padding: '32px', borderRadius: '24px', display: 'flex', flexDirection: 'column', height: '100%' }}>
                <div style={{ fontSize: '40px', marginBottom: '20px' }}>👨🏻‍💻</div>
                <h3 style={{ fontSize: '24px', fontWeight: 600, margin: '0 0 8px 0', color: '#fff' }}>Raul Cortinas</h3>
                <div style={{ fontSize: '14px', color: '#10B981', fontWeight: 500, marginBottom: '16px' }}>Backend Architect</div>
                <p style={{ fontSize: '16px', color: 'rgba(255,255,255,0.6)', lineHeight: 1.6, margin: 0 }}>
                  Raul built the engine under the hood. He designed the systems that allow IntelliCloud to process massive amounts of network data instantly and securely.
                </p>
              </div>
            </FadeIn>

            {/* Bryan */}
            <FadeIn delay={200}>
              <div className="glass-panel" style={{ padding: '32px', borderRadius: '24px', display: 'flex', flexDirection: 'column', height: '100%' }}>
                <div style={{ fontSize: '40px', marginBottom: '20px' }}>👨🏼‍💻</div>
                <h3 style={{ fontSize: '24px', fontWeight: 600, margin: '0 0 8px 0', color: '#fff' }}>Bryan Kahl</h3>
                <div style={{ fontSize: '14px', color: '#3E7BFF', fontWeight: 500, marginBottom: '16px' }}>Frontend & AI Specialist</div>
                <p style={{ fontSize: '16px', color: 'rgba(255,255,255,0.6)', lineHeight: 1.6, margin: 0 }}>
                  Bryan made it simple to use. He built the clean interface you see today and integrated the AI that translates confusing code into plain English.
                </p>
              </div>
            </FadeIn>

          </div>
        </div>

      </div>
    </div>
  );
}