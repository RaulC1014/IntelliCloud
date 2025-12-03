// src/pages/Decipher.jsx
import React, { useState, useEffect } from 'react';

// --- Morse Code Dictionary ---
const MORSE_MAP = {
  'A': '.-', 'B': '-...', 'C': '-.-.', 'D': '-..', 'E': '.', 'F': '..-.', 'G': '--.', 'H': '....', 'I': '..', 'J': '.---', 'K': '-.-', 'L': '.-..', 'M': '--', 'N': '-.', 'O': '---', 'P': '.--.', 'Q': '--.-', 'R': '.-.', 'S': '...', 'T': '-', 'U': '..-', 'V': '...-', 'W': '.--', 'X': '-..-', 'Y': '-.--', 'Z': '--..',
  '1': '.----', '2': '..---', '3': '...--', '4': '....-', '5': '.....', '6': '-....', '7': '--...', '8': '---..', '9': '----.', '0': '-----', ' ': '/'
};
const REVERSE_MORSE = Object.fromEntries(Object.entries(MORSE_MAP).map(([k, v]) => [v, k]));

// --- Algorithms ---
const ciphers = {
  base64: {
    name: 'Base64',
    desc: 'Encode binary data into ASCII characters.',
    encode: (s) => { try { return btoa(s); } catch { return 'Error: Input must be valid ASCII for Base64.'; } },
    decode: (s) => { try { return atob(s); } catch { return 'Invalid Base64 string.'; } }
  },
  hex: {
    name: 'Hexadecimal',
    desc: 'Convert text to hexadecimal bytes.',
    encode: (s) => s.split('').map(c => c.charCodeAt(0).toString(16).padStart(2, '0')).join(' '),
    decode: (s) => {
      try {
        const hex = s.replace(/\s+/g, '');
        if (hex.length % 2 !== 0) return 'Invalid Hex (odd length)';
        let str = '';
        for (let i = 0; i < hex.length; i += 2) str += String.fromCharCode(parseInt(hex.substr(i, 2), 16));
        return str;
      } catch { return 'Invalid Hex'; }
    }
  },
  rot13: {
    name: 'ROT13',
    desc: 'Rotate characters by 13 places (Caesar Cipher variant).',
    encode: (s) => s.replace(/[a-zA-Z]/g, c => String.fromCharCode((c <= 'Z' ? 90 : 122) >= (c = c.charCodeAt(0) + 13) ? c : c - 26)),
    decode: (s) => s.replace(/[a-zA-Z]/g, c => String.fromCharCode((c <= 'Z' ? 90 : 122) >= (c = c.charCodeAt(0) + 13) ? c : c - 26))
  },
  atbash: {
    name: 'Atbash',
    desc: 'Reverses the alphabet (A becomes Z, B becomes Y).',
    encode: (s) => s.replace(/[a-zA-Z]/g, c => {
      const base = c <= 'Z' ? 65 : 97;
      return String.fromCharCode(base + (25 - (c.charCodeAt(0) - base)));
    }),
    decode: (s) => s.replace(/[a-zA-Z]/g, c => {
      const base = c <= 'Z' ? 65 : 97;
      return String.fromCharCode(base + (25 - (c.charCodeAt(0) - base)));
    })
  },
  morse: {
    name: 'Morse Code',
    desc: 'Dots and dashes. Use / for space.',
    encode: (s) => s.toUpperCase().split('').map(c => MORSE_MAP[c] || c).join(' '),
    decode: (s) => s.split(' ').map(c => REVERSE_MORSE[c] || c).join('')
  },
  railfence: {
    name: 'Rail Fence',
    desc: 'Zig-zag transposition cipher.',
    requiresKey: true,
    keyLabel: 'Rails (Number)',
    defaultKey: '3',
    encode: (s, key) => {
      const rails = parseInt(key) || 3;
      if (rails < 2) return s;
      let fence = Array(rails).fill().map(() => []);
      let rail = 0, dir = 1;
      for (let c of s) {
        fence[rail].push(c);
        rail += dir;
        if (rail === 0 || rail === rails - 1) dir = -dir;
      }
      return fence.flat().join('');
    },
    decode: (s, key) => {
      const rails = parseInt(key) || 3;
      if (rails < 2) return s;
      const len = s.length;
      let fence = Array(rails).fill().map(() => Array(len).fill(null));
      let rail = 0, dir = 1;
      
      // Mark spots
      for (let i = 0; i < len; i++) {
        fence[rail][i] = '?';
        rail += dir;
        if (rail === 0 || rail === rails - 1) dir = -dir;
      }
      
      // Fill text
      let index = 0;
      for (let r = 0; r < rails; r++) {
        for (let c = 0; c < len; c++) {
          if (fence[r][c] === '?' && index < len) fence[r][c] = s[index++];
        }
      }
      
      // Read Zig-Zag
      let res = '';
      rail = 0; dir = 1;
      for (let i = 0; i < len; i++) {
        res += fence[rail][i];
        rail += dir;
        if (rail === 0 || rail === rails - 1) dir = -dir;
      }
      return res;
    }
  },
  vigenere: {
    name: 'Vigenère',
    desc: 'Polyalphabetic substitution using a keyword.',
    requiresKey: true,
    keyLabel: 'Secret Key (Text)',
    defaultKey: 'KEY',
    encode: (s, key) => {
      if (!key) return s;
      const k = key.toUpperCase().replace(/[^A-Z]/g, '');
      if (!k) return s;
      let ki = 0;
      return s.replace(/[a-zA-Z]/g, c => {
        const base = c <= 'Z' ? 65 : 97;
        const shift = k[ki++ % k.length].charCodeAt(0) - 65;
        return String.fromCharCode(base + (c.charCodeAt(0) - base + shift) % 26);
      });
    },
    decode: (s, key) => {
      if (!key) return s;
      const k = key.toUpperCase().replace(/[^A-Z]/g, '');
      if (!k) return s;
      let ki = 0;
      return s.replace(/[a-zA-Z]/g, c => {
        const base = c <= 'Z' ? 65 : 97;
        const shift = k[ki++ % k.length].charCodeAt(0) - 65;
        return String.fromCharCode(base + (c.charCodeAt(0) - base - shift + 26) % 26);
      });
    }
  }
};

export default function Decipher() {
  const [activeTool, setActiveTool] = useState('base64');
  const [mode, setMode] = useState('encode');
  const [input, setInput] = useState('');
  const [cipherKey, setCipherKey] = useState('');
  const [output, setOutput] = useState('');

  // Auto-run when inputs change
  useEffect(() => {
    const tool = ciphers[activeTool];
    
    // Set default key if empty and tool requires one
    if (tool.requiresKey && !cipherKey) {
        setCipherKey(tool.defaultKey);
    }

    if (!input) { setOutput(''); return; }
    
    // Run cipher
    const res = mode === 'encode' 
      ? tool.encode(input, cipherKey) 
      : tool.decode(input, cipherKey);
      
    setOutput(String(res));
  }, [input, activeTool, mode, cipherKey]);

  const copyToClipboard = () => {
    navigator.clipboard.writeText(output);
    alert('Output copied to clipboard');
  };

  const tool = ciphers[activeTool];

  return (
    <div className="shell page-decipher animate-fade" style={{ maxWidth: 1400, marginTop: 20 }}>
      
      <div style={{ display: 'grid', gridTemplateColumns: '260px 1fr', gap: 24, minHeight: '70vh' }}>
        
        {/* SIDEBAR */}
        <div className="card animate-slide" style={{ padding: 0, overflow: 'hidden', height: 'fit-content' }}>
          <div style={{ padding: 20, background: 'var(--panel-2)', borderBottom: '1px solid var(--border)' }}>
            <h3 style={{ margin: 0, fontSize: 16 }}>Ciphers</h3>
          </div>
          <div style={{ padding: 12 }}>
            {Object.keys(ciphers).map(key => (
              <button 
                key={key}
                onClick={() => { setActiveTool(key); setCipherKey(ciphers[key].defaultKey || ''); }}
                className="btn"
                style={{ 
                  width: '100%', justifyContent: 'flex-start', marginBottom: 8,
                  background: activeTool === key ? 'var(--brand)' : 'transparent',
                  color: activeTool === key ? 'white' : 'var(--text)',
                  border: activeTool === key ? 'none' : '1px solid transparent',
                  fontWeight: 600
                }}
              >
                {ciphers[key].name}
              </button>
            ))}
          </div>
        </div>

        {/* MAIN WORKSPACE */}
        <div className="card animate-slide animate-delay-1" style={{ display: 'flex', flexDirection: 'column' }}>
          
          {/* Header */}
          <div style={{ marginBottom: 24, display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <div>
              <h2 className="h1" style={{ fontSize: 24, margin: 0 }}>{tool.name}</h2>
              <p className="p-muted" style={{ margin: 0 }}>{tool.desc}</p>
            </div>
            
            {/* Mode Switcher */}
            <div style={{ background: 'var(--input)', padding: 4, borderRadius: 8, display: 'flex' }}>
              <button 
                onClick={() => setMode('encode')}
                style={{ 
                  padding: '8px 24px', borderRadius: 6, border: 'none', cursor: 'pointer', fontWeight: 600,
                  background: mode === 'encode' ? 'var(--panel)' : 'transparent',
                  color: mode === 'encode' ? 'var(--brand)' : 'var(--muted)',
                  boxShadow: mode === 'encode' ? '0 2px 8px rgba(0,0,0,0.2)' : 'none'
                }}
              >
                Encode
              </button>
              <button 
                onClick={() => setMode('decode')}
                style={{ 
                  padding: '8px 24px', borderRadius: 6, border: 'none', cursor: 'pointer', fontWeight: 600,
                  background: mode === 'decode' ? 'var(--panel)' : 'transparent',
                  color: mode === 'decode' ? 'var(--brand)' : 'var(--muted)',
                  boxShadow: mode === 'decode' ? '0 2px 8px rgba(0,0,0,0.2)' : 'none'
                }}
              >
                Decode
              </button>
            </div>
          </div>

          {/* DYNAMIC KEY INPUT (Shows only if needed) */}
          {tool.requiresKey && (
            <div className="animate-fade" style={{ marginBottom: 20 }}>
                <label className="label" style={{color:'var(--brand)'}}>{tool.keyLabel}</label>
                <input 
                    className="input" 
                    value={cipherKey} 
                    onChange={e => setCipherKey(e.target.value)}
                    placeholder={tool.defaultKey}
                    style={{ borderColor: 'var(--brand)' }}
                />
            </div>
          )}

          {/* Input / Output Grid */}
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 24, flex: 1 }}>
            
            {/* INPUT */}
            <div style={{ display: 'flex', flexDirection: 'column' }}>
              <label className="label">Input Payload</label>
              <textarea 
                className="input mono" 
                style={{ flex: 1, resize: 'none', minHeight: 400, fontSize: 14, lineHeight: 1.6 }}
                placeholder="Paste text here..."
                value={input}
                onChange={e => setInput(e.target.value)}
              />
            </div>

            {/* OUTPUT */}
            <div style={{ display: 'flex', flexDirection: 'column' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 6 }}>
                <label className="label">Result</label>
                <button onClick={copyToClipboard} style={{ background: 'none', border: 'none', color: 'var(--brand)', cursor: 'pointer', fontSize: 12, fontWeight: 700 }}>
                  Copy Output
                </button>
              </div>
              <textarea 
                className="input mono" 
                readOnly
                style={{ flex: 1, resize: 'none', minHeight: 400, fontSize: 14, lineHeight: 1.6, background: 'var(--panel-2)', borderColor: 'var(--brand)' }}
                placeholder="Result will appear here..."
                value={output}
              />
            </div>

          </div>

        </div>

      </div>
    </div>
  );
}