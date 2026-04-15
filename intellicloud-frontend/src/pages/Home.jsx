// src/pages/Home.jsx
import React, { useEffect, useRef, useState } from 'react';

// --- Soft, Minimal Icons ---
const EyeIcon = () => <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"></path><circle cx="12" cy="12" r="3"></circle></svg>;
const TranslateIcon = () => <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5"><path d="M4 19V5a2 2 0 0 1 2-2h13.4a2 2 0 0 1 2 2v13.8a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2z"></path><path d="M9 9h6"></path><path d="M9 13h6"></path><path d="M9 17h3"></path></svg>;
const ActivityIcon = () => <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"></polyline></svg>;

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

// --- Interactive Info Tabs Component ---
function InfoTabs() {
  const [activeTab, setActiveTab] = useState(0);

  const tabs = [
    {
      id: 0,
      icon: <EyeIcon />,
      title: "1. See Everything",
      headline: "We monitor your network with zero blind spots.",
      content: "IntelliCloud quietly sits on your network, taking split-second snapshots of all traffic. We maintain deep visibility into every packet, connection, and payload, ensuring absolutely nothing slips by unnoticed."
    },
    {
      id: 1,
      icon: <TranslateIcon />,
      title: "2. Understand Anything",
      headline: "We translate raw data into plain English.",
      content: "When suspicious activity is detected, you usually get a confusing wall of hex and numbers. Our engine instantly analyzes the attacker's payload and tells you exactly what they are doing, like: 'Someone is probing your database for vulnerabilities.'"
    },
    {
      id: 2,
      icon: <ActivityIcon />,
      title: "3. Absolute Observation",
      headline: "Deep intelligence, zero interference.",
      content: "We are the ultimate observers. IntelliCloud does not block traffic or disrupt your infrastructure. Instead, we give your security team the critical context, historical trends, and translated intelligence they need to make the right decisions."
    }
  ];

  return (
    <div className="glass-panel" style={{ padding: '40px', borderRadius: '24px', marginTop: '60px' }}>
      <div style={{ display: 'flex', gap: '20px', marginBottom: '40px', borderBottom: '1px solid rgba(255,255,255,0.1)', paddingBottom: '20px', overflowX: 'auto' }}>
        {tabs.map((tab) => (
          <button
            key={tab.id}
            onClick={() => setActiveTab(tab.id)}
            style={{
              background: 'none',
              border: 'none',
              color: activeTab === tab.id ? '#fff' : 'rgba(255,255,255,0.4)',
              fontSize: '16px',
              fontWeight: 500,
              cursor: 'pointer',
              display: 'flex',
              alignItems: 'center',
              gap: '10px',
              padding: '10px 20px',
              borderRadius: '30px',
              backgroundColor: activeTab === tab.id ? 'rgba(255,255,255,0.1)' : 'transparent',
              transition: 'all 0.3s ease',
              whiteSpace: 'nowrap'
            }}
          >
            {tab.icon}
            {tab.title}
          </button>
        ))}
      </div>
      
      <div style={{ minHeight: '180px' }}>
        <h3 style={{ fontSize: '28px', fontWeight: 600, margin: '0 0 16px 0', color: '#fff' }}>
          {tabs[activeTab].headline}
        </h3>
        <p style={{ fontSize: '18px', color: 'rgba(255,255,255,0.7)', lineHeight: 1.6, maxWidth: '800px', margin: 0 }}>
          {tabs[activeTab].content}
        </p>
      </div>
    </div>
  );
}

export default function Home({ user }) {
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
          <InfoTabs />
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