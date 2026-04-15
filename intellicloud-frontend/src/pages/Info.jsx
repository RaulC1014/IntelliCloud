// src/pages/Info.jsx
import React from 'react';
import { FadeIn } from './Home.jsx';

export default function Info() {
  return (
    <div style={{ fontFamily: '"Inter", -apple-system, sans-serif', paddingBottom: '80px' }}>
      <div style={{ maxWidth: 900, margin: '0 auto', paddingTop: '40px' }}>
        
        <FadeIn>
          <h1 className="gradient-text" style={{ fontSize: '48px', fontWeight: 700, marginBottom: '12px' }}>
            About IntelliCloud
          </h1>
          <p style={{ fontSize: '18px', color: 'rgba(255,255,255,0.6)', marginBottom: '48px' }}>
            Senior Capstone Project · Created by Raul Cortinas & Bryan Kahl
          </p>
        </FadeIn>

        <FadeIn delay={100}>
          <div className="glass-panel" style={{ padding: '32px', borderRadius: '20px', marginBottom: '32px' }}>
            <h2 style={{ fontSize: '24px', fontWeight: 600, marginBottom: '16px', color: '#fff' }}>Project Overview</h2>
            <p style={{ fontSize: '16px', color: 'rgba(255,255,255,0.7)', lineHeight: 1.7, margin: 0 }}>
              IntelliCloud is a secure cloud-native threat intelligence platform designed to help security teams detect, track, and manage cyber threats targeting cloud-based infrastructures. It provides both backend services and an interactive frontend dashboard to deliver real-time insights into suspicious activity.
            </p>
          </div>
        </FadeIn>

        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(400px, 1fr))', gap: '32px' }}>
          
          <FadeIn delay={200}>
            <div className="glass-panel" style={{ padding: '32px', borderRadius: '20px', height: '100%' }}>
              <h2 style={{ fontSize: '24px', fontWeight: 600, marginBottom: '24px', color: '#fff' }}>Key Capabilities</h2>
              <ul style={{ listStyle: 'none', padding: 0, margin: 0, display: 'flex', flexDirection: 'column', gap: '16px' }}>
                <li style={{ color: 'rgba(255,255,255,0.7)', lineHeight: 1.5 }}>
                  <strong style={{ color: '#fff' }}>Live Threat Monitoring:</strong> View and filter suspicious IPs, attack patterns, and threat levels (1-10 scale).
                </li>
                <li style={{ color: 'rgba(255,255,255,0.7)', lineHeight: 1.5 }}>
                  <strong style={{ color: '#fff' }}>User-Specific Data Access:</strong> Secure access managed via Firebase Authentication.
                </li>
                <li style={{ color: 'rgba(255,255,255,0.7)', lineHeight: 1.5 }}>
                  <strong style={{ color: '#fff' }}>Audit Logging:</strong> Tracks user actions on the platform for accountability.
                </li>
                <li style={{ color: 'rgba(255,255,255,0.7)', lineHeight: 1.5 }}>
                  <strong style={{ color: '#3E7BFF' }}>Role-Based Access Control (Soon):</strong> Different levels of access for analysts, admins, and auditors.
                </li>
                <li style={{ color: 'rgba(255,255,255,0.7)', lineHeight: 1.5 }}>
                  <strong style={{ color: '#3E7BFF' }}>Historical Trends (Soon):</strong> Visualization of past attacks over time.
                </li>
              </ul>
            </div>
          </FadeIn>

          <FadeIn delay={300}>
            <div className="glass-panel" style={{ padding: '32px', borderRadius: '20px', height: '100%' }}>
              <h2 style={{ fontSize: '24px', fontWeight: 600, marginBottom: '24px', color: '#fff' }}>Technology Stack</h2>
              
              <div style={{ marginBottom: '20px' }}>
                <h3 style={{ fontSize: '14px', textTransform: 'uppercase', color: '#10B981', letterSpacing: '1px', marginBottom: '12px' }}>Frontend</h3>
                <div style={{ display: 'flex', flexWrap: 'wrap', gap: '8px' }}>
                  {['React.js', 'Axios', 'Firebase Auth'].map(tech => (
                    <span key={tech} style={{ padding: '6px 12px', background: 'rgba(255,255,255,0.05)', borderRadius: '6px', fontSize: '14px', color: 'rgba(255,255,255,0.8)' }}>{tech}</span>
                  ))}
                </div>
              </div>

              <div style={{ marginBottom: '20px' }}>
                <h3 style={{ fontSize: '14px', textTransform: 'uppercase', color: '#3E7BFF', letterSpacing: '1px', marginBottom: '12px' }}>Backend</h3>
                <div style={{ display: 'flex', flexWrap: 'wrap', gap: '8px' }}>
                  {['Python Flask API', 'PostgreSQL', 'Firebase Admin SDK', 'psycopg2-binary', 'Flask-CORS'].map(tech => (
                    <span key={tech} style={{ padding: '6px 12px', background: 'rgba(255,255,255,0.05)', borderRadius: '6px', fontSize: '14px', color: 'rgba(255,255,255,0.8)' }}>{tech}</span>
                  ))}
                </div>
              </div>

              <div>
                <h3 style={{ fontSize: '14px', textTransform: 'uppercase', color: '#F59E0B', letterSpacing: '1px', marginBottom: '12px' }}>Database</h3>
                <div style={{ display: 'flex', flexWrap: 'wrap', gap: '8px' }}>
                  {['PostgreSQL', 'pgAdmin4'].map(tech => (
                    <span key={tech} style={{ padding: '6px 12px', background: 'rgba(255,255,255,0.05)', borderRadius: '6px', fontSize: '14px', color: 'rgba(255,255,255,0.8)' }}>{tech}</span>
                  ))}
                </div>
              </div>

            </div>
          </FadeIn>

        </div>
      </div>
    </div>
  );
}