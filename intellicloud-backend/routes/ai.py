import os
import logging
import json
from flask import Blueprint, request, jsonify
import google.generativeai as genai

ai_bp = Blueprint('ai', __name__)
logger = logging.getLogger(__name__)

# Configure API Key
api_key = os.getenv("GEMINI_API_KEY")
if api_key:
    genai.configure(api_key=api_key)

@ai_bp.route('/chat', methods=['POST'])
def chat_with_context():
    if not api_key:
        return jsonify({
            "response": "⚠️ **System Error**: Neural Core Offline (Missing API Key)."
        })

    try:
        data = request.json
        messages = data.get('messages', [])
        raw_context = data.get('context', {})

        # --- 1. ENHANCED CONTEXT EXTRACTION ---
        # We parse the incoming frontend data to give the AI full situational awareness.
        c = {
            "src_ip": raw_context.get('src', 'Unknown'),
            "src_loc": f"{raw_context.get('src_city', 'Unknown City')}, {raw_context.get('src_cc', 'Unknown Country')}",
            "src_org": raw_context.get('src_asnorg', 'Unknown ISP'),
            
            "dst_ip": raw_context.get('dst', 'Internal Asset'),
            "dst_loc": f"{raw_context.get('dst_city', '')}, {raw_context.get('dst_cc', '')}".strip(', '),
            
            "proto": raw_context.get('proto', 'TCP'),
            "port": raw_context.get('dport', 'Unknown'),
            "flow": raw_context.get('flow', 'Inbound'), # Inbound/Outbound
            "severity": raw_context.get('level', 'Low'),
            "dns": raw_context.get('dns', 'N/A')
        }

        # --- 2. DYNAMIC SYSTEM PROMPT ---
        system_instruction = f"""
        You are 'IntelliCloud', a Tier-3 Senior Security Operations Center (SOC) Analyst.
        Your goal is to analyze network traffic logs and provide actionable, executive-level security guidance.
        
        === THREAT INTELLIGENCE ===
        Target Asset: {c['dst_ip']} ({c['dst_loc']})
        Attacker Source: {c['src_ip']} 
        Attacker Location: {c['src_loc']}
        Attacker ISP/Org: {c['src_org']}
        
        Traffic Vector: {c['flow']} {c['proto']} Traffic on Port {c['port']}
        Severity Level: {c['severity']}
        DNS Resolution: {c['dns']}

        === YOUR INSTRUCTIONS ===
        1. **Analyze the Port & Protocol**: 
           - If Port 22 (SSH) or 3389 (RDP): Assume brute-force or unauthorized admin access attempts.
           - If Port 80/443 (HTTP/S): Assume web-application scanning, SQLi, or XSS probing.
           - If Port 53 (DNS): Check for tunneling or amplification.
           - If High Port (>1024): Check if it's a dynamic service or malware C2 callback.

        2. **Analyze the Geography**:
           - Is the traffic coming from a high-risk region or unexpected ISP (e.g., Residential ISP vs Data Center)?

        3. **Analyze the Direction**:
           - **Inbound**: Someone is trying to get IN (Breach attempt).
           - **Outbound**: A server is trying to get OUT (Data Exfiltration or Malware Callback).

        === RESPONSE FORMAT ===
        Keep your response "Concise, Clear, and Actionable". Do not use markdown headers (#). Use bolding for emphasis.
        
        **Analysis:** [1-2 sentences explaining what this traffic actually IS. E.g., "This is an inbound connection attempt on the remote desktop port from a residential ISP in Russia."]

        **Risk:** [Explain the business risk. E.g., "If successful, the attacker could gain full administrative control of your server and deploy ransomware."]

        **Recommendation:**
        [Bullet points of specific actions. Use strong verbs.]
        • Block IP {c['src_ip']} immediately.
        • [Specific advice based on port, e.g., "Disable RDP access to the public internet."]
        • [Audit advice, e.g., "Check logs for successful logins."]
        """

        # --- 3. EXECUTE MODEL ---
        model = genai.GenerativeModel(
            model_name='gemini-2.0-flash', 
            system_instruction=system_instruction
        )

        # Convert Chat History for Gemini Format
        history = []
        for msg in messages[:-1]:
            role = "user" if msg['role'] == 'user' else "model"
            history.append({"role": role, "parts": [msg['content']]})

        chat = model.start_chat(history=history)
        
        # If the user just clicked "Ask AI" without typing, use a default trigger.
        user_prompt = messages[-1]['content'] if messages else "Analyze this threat."
        
        response = chat.send_message(user_prompt)

        return jsonify({"response": response.text})

    except Exception as e:
        logger.error(f"AI Error: {traceback.format_exc()}")
        return jsonify({
            "response": "⚠️ **Analysis Failed**\nUnable to reach the IntelliCloud Neural Core. Please verify your internet connection and API keys."
        })