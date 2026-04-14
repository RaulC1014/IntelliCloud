import os
import logging
import traceback
from flask import Blueprint, request, jsonify
from auth import require_auth
from google import genai
from google.genai import types

ai_bp = Blueprint('ai', __name__)
logger = logging.getLogger(__name__)

api_key = os.getenv("GEMINI_API_KEY")
client = genai.Client(api_key=api_key) if api_key else None


def _build_system_prompt(c: dict) -> str:
    """
    Build a dynamic system prompt based on the event type and available context.
    Each event type gets tailored analysis instructions.
    """
    event_type = c.get("event_type", "").upper()
    severity   = c.get("severity", "Low")
    src        = c.get("src_ip", "Unknown")
    dst        = c.get("dst_ip", "Unknown")
    proto      = c.get("proto", "Unknown").upper()
    dport      = c.get("dport") or c.get("dst_port", "Unknown")
    sport      = c.get("sport") or c.get("src_port", "Unknown")
    direction  = c.get("direction") or c.get("dir", "unknown")
    dns        = c.get("dns") or c.get("dns_qname", "N/A")
    dns_answers= c.get("dns_answers", [])
    reason     = c.get("reason", "")
    detection  = c.get("detectionType") or c.get("detection_type", "")
    src_zone   = c.get("src_zone", "unknown")
    dst_zone   = c.get("dst_zone", "unknown")
    src_loc    = f"{c.get('src_city','')} {c.get('src_cc','')}".strip() or "Unknown"
    src_org    = c.get("src_asnorg", "Unknown ISP")
    tcp_flags  = c.get("tcp_flags_str", "")
    icmp_type  = c.get("icmp_type_name", "")
    arp_warn   = c.get("warning", "")
    hw_src     = c.get("hw_src", "")
    hw_dst     = c.get("hw_dst", "")
    pkt_delta  = c.get("packets_delta", "")
    byte_delta = c.get("bytes_delta", "")
    ttl        = c.get("ttl", "")

    # ── Build event-specific context block ──────────────────────────────────
    if event_type == "ARP_SPOOFING_ALERT":
        event_context = f"""
EVENT TYPE: ARP Spoofing Alert — CRITICAL
Warning: {arp_warn}
Source MAC: {hw_src}  →  Source IP: {src}
Destination MAC: {hw_dst}  →  Destination IP: {dst}
Network Zone: {src_zone}

ARP spoofing means an attacker is broadcasting fake ARP replies to poison the ARP cache of
devices on the LAN, redirecting their traffic through the attacker's machine (MITM attack).
"""

    elif event_type in ("DNS_QUERY", "DNS_RESPONSE"):
        dns_answer_str = ", ".join(dns_answers) if dns_answers else "No answer records captured"
        event_context = f"""
EVENT TYPE: {event_type.replace('_', ' ').title()}
Querying Host: {src} ({src_zone})
DNS Server: {dst}
Domain: {dns}
Resolved To: {dns_answer_str}
Direction: {direction}
"""

    elif event_type in ("TCP_SYN", "TCP_CONNECT_ATTEMPT"):
        event_context = f"""
EVENT TYPE: TCP Connection Attempt (SYN)
Source: {src}:{sport} ({src_zone}) — {src_loc} / {src_org}
Destination: {dst}:{dport} ({dst_zone})
Direction: {direction}
TCP Flags: {tcp_flags}
TTL: {ttl}
Detection: {detection}
Reason: {reason}
"""

    elif event_type == "TCP_RST":
        event_context = f"""
EVENT TYPE: TCP RST (Connection Reset/Rejected)
Source: {src}:{sport} ({src_zone})
Destination: {dst}:{dport} ({dst_zone})
Direction: {direction}
TCP Flags: {tcp_flags}
TTL: {ttl}

RST packets indicate a port was closed, a firewall rejected the connection, or a device
is actively refusing connections. Mass RST responses often indicate a port scan in progress.
"""

    elif event_type == "TCP_FIN":
        event_context = f"""
EVENT TYPE: TCP FIN (Session Teardown)
Source: {src}:{sport} ({src_zone})
Destination: {dst}:{dport} ({dst_zone})
Direction: {direction}
TCP Flags: {tcp_flags}

A graceful TCP session close. Low severity on its own but useful for session tracking.
"""

    elif event_type == "ICMP":
        event_context = f"""
EVENT TYPE: ICMP — {icmp_type}
Source: {src} ({src_zone}) — {src_loc}
Destination: {dst} ({dst_zone})
ICMP Type: {icmp_type}
TTL: {ttl}
Direction: {direction}
"""

    elif event_type == "ARP":
        event_context = f"""
EVENT TYPE: ARP {c.get('arp_op_name', '')}
Source: {src} (MAC: {hw_src})
Target: {dst} (MAC: {hw_dst})
Network Zone: {src_zone}
"""

    elif event_type == "FLOW_SUMMARY":
        event_context = f"""
EVENT TYPE: Flow Summary (aggregated traffic)
Source: {src}:{sport} ({src_zone})
Destination: {dst}:{dport} ({dst_zone})
Protocol: {proto}
Direction: {direction}
Packets (this window): {pkt_delta}
Bytes (this window): {byte_delta}
App Layer: {c.get('app', 'Unknown')}
"""

    else:
        # Generic fallback for any other event type
        event_context = f"""
EVENT TYPE: {event_type or 'Network Event'}
Source: {src}:{sport} ({src_zone}) — {src_loc} / {src_org}
Destination: {dst}:{dport} ({dst_zone})
Protocol: {proto}
Direction: {direction}
TCP Flags: {tcp_flags}
TTL: {ttl}
DNS: {dns}
Detection: {detection}
Reason: {reason}
"""

    # ── Full system prompt ───────────────────────────────────────────────────
    return f"""You are IntelliCloud, a Tier-3 Senior SOC Analyst with expertise in network forensics,
threat hunting, and incident response. You are analyzing a specific network security event captured
by the IntelliCloud sensor.

=== EVENT DATA ===
Severity: {severity}
{event_context.strip()}

=== YOUR ANALYSIS INSTRUCTIONS ===

1. IDENTIFY what this event actually is — not just the technical description, but what it means
   in practice. Is this normal? Suspicious? Definitively malicious?

2. ASSESS the risk based on:
   - The event type and what it implies (ARP spoofing = active MITM, port scan RSTs = reconnaissance,
     DNS to unusual IPs = possible C2, etc.)
   - The direction (inbound = someone targeting you, outbound = possible exfiltration or callback)
   - The zone (public→private = external attacker, private→private = lateral movement or insider)
   - The severity label the detection engine assigned

3. RECOMMEND specific, immediately actionable steps. Be direct. Use strong verbs.
   Do not give generic advice. Tailor your recommendation to the specific event type.

=== RESPONSE FORMAT ===
Use plain text. Do not use markdown headers (#). Bold key terms with **.

**What This Is:** [1-2 sentences. What is actually happening, in plain English.]

**Risk:** [1-2 sentences. What could happen if this is malicious and not addressed.]

**Recommended Actions:**
- [Specific action 1]
- [Specific action 2]
- [Specific action 3]

Keep the entire response under 200 words. Be precise, not verbose.
"""


@ai_bp.route('/chat', methods=['POST'])
@require_auth
def chat_with_context():
    if not client:
        return jsonify({
            "response": "⚠️ **Neural Core Offline** — GEMINI_API_KEY is not configured."
        })

    try:
        data = request.json or {}
        messages = data.get('messages', [])
        raw_context = data.get('context', {})

        if not messages:
            return jsonify({"response": "No messages provided."}), 400

        system_instruction = _build_system_prompt(raw_context)

        # Build conversation history
        contents = []
        for msg in messages[:-1]:
            role = "user" if msg['role'] == 'user' else "model"
            contents.append(types.Content(
                role=role,
                parts=[types.Part(text=msg['content'])]
            ))

        user_prompt = messages[-1]['content'] if messages else "Analyze this event."
        contents.append(types.Content(
            role="user",
            parts=[types.Part(text=user_prompt)]
        ))

        response = client.models.generate_content(
            model="gemini-2.0-flash",
            contents=contents,
            config=types.GenerateContentConfig(
                system_instruction=system_instruction,
                max_output_tokens=400,
                temperature=0.3,   # lower = more consistent, factual responses
            ),
        )

        return jsonify({"response": response.text})

    except Exception as e:
        logger.error(f"AI Error: {traceback.format_exc()}")
        return jsonify({
            "response": "⚠️ **Analysis Failed** — Unable to reach the IntelliCloud Neural Core."
        })