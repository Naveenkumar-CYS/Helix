"""
Demonstration Dashboard for Live Presentations
Shows real-time attack analysis with detailed LLM thinking and intelligence processing.
"""

from typing import Dict, List, Any, Optional
from datetime import datetime
import json


# Global storage for demonstration data
_demo_data = {
    "current_attack": None,
    "llm_thinking": [],
    "analysis_steps": [],
    "threat_intel": {},
    "behavioral_profile": {},
    "fingerprint_data": {},
}


def get_demo_dashboard_html() -> str:
    """Get enhanced demonstration dashboard HTML."""
    return """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>AI Honeypot - Live Demonstration</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: 'Consolas', 'Monaco', monospace;
            background: #0a0e27;
            color: #00ff41;
            padding: 20px;
            overflow-x: hidden;
        }
        
        .container {
            max-width: 1800px;
            margin: 0 auto;
        }
        
        header {
            text-align: center;
            margin-bottom: 30px;
            padding: 20px;
            background: linear-gradient(135deg, #1a1f3a 0%, #2d3561 100%);
            border-radius: 10px;
            border: 2px solid #00ff41;
            box-shadow: 0 0 20px rgba(0, 255, 65, 0.3);
        }
        
        h1 {
            font-size: 2.5em;
            margin-bottom: 10px;
            text-shadow: 0 0 10px #00ff41;
            animation: glow 2s ease-in-out infinite alternate;
        }
        
        @keyframes glow {
            from { text-shadow: 0 0 10px #00ff41, 0 0 20px #00ff41; }
            to { text-shadow: 0 0 20px #00ff41, 0 0 30px #00ff41, 0 0 40px #00ff41; }
        }
        
        .subtitle {
            font-size: 1.2em;
            color: #00d4ff;
        }
        
        .status-indicator {
            display: inline-block;
            width: 12px;
            height: 12px;
            border-radius: 50%;
            background: #00ff41;
            animation: pulse 1.5s infinite;
            margin-right: 8px;
        }
        
        @keyframes pulse {
            0%, 100% { opacity: 1; transform: scale(1); }
            50% { opacity: 0.5; transform: scale(1.2); }
        }
        
        .main-grid {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 20px;
            margin-bottom: 20px;
        }
        
        .full-width {
            grid-column: 1 / -1;
        }
        
        .panel {
            background: rgba(26, 31, 58, 0.8);
            border: 2px solid #00ff41;
            border-radius: 10px;
            padding: 20px;
            box-shadow: 0 0 15px rgba(0, 255, 65, 0.2);
        }
        
        .panel h2 {
            font-size: 1.5em;
            margin-bottom: 15px;
            color: #00d4ff;
            border-bottom: 2px solid #00ff41;
            padding-bottom: 10px;
        }
        
        .attack-display {
            background: rgba(0, 0, 0, 0.5);
            border: 1px solid #ff0066;
            border-radius: 8px;
            padding: 15px;
            margin-bottom: 15px;
            animation: slideIn 0.5s ease-out;
        }
        
        @keyframes slideIn {
            from { opacity: 0; transform: translateX(-20px); }
            to { opacity: 1; transform: translateX(0); }
        }
        
        .attack-label {
            color: #ff0066;
            font-weight: bold;
            margin-bottom: 5px;
        }
        
        .attack-value {
            color: #00ff41;
            font-size: 1.1em;
            word-break: break-all;
        }
        
        .thinking-step {
            background: rgba(0, 212, 255, 0.1);
            border-left: 4px solid #00d4ff;
            padding: 12px;
            margin-bottom: 10px;
            border-radius: 5px;
            animation: fadeIn 0.3s ease-out;
        }
        
        @keyframes fadeIn {
            from { opacity: 0; }
            to { opacity: 1; }
        }
        
        .thinking-step .step-number {
            color: #00d4ff;
            font-weight: bold;
            margin-right: 10px;
        }
        
        .thinking-step .step-content {
            color: #ffffff;
        }
        
        .analysis-item {
            display: flex;
            justify-content: space-between;
            padding: 10px;
            margin-bottom: 8px;
            background: rgba(0, 255, 65, 0.05);
            border-radius: 5px;
            border: 1px solid rgba(0, 255, 65, 0.2);
        }
        
        .analysis-label {
            color: #00d4ff;
        }
        
        .analysis-value {
            color: #00ff41;
            font-weight: bold;
        }
        
        .threat-badge {
            display: inline-block;
            padding: 5px 15px;
            border-radius: 20px;
            font-size: 0.9em;
            font-weight: bold;
            margin: 5px;
        }
        
        .threat-low { background: #00ff41; color: #0a0e27; }
        .threat-medium { background: #ffd700; color: #0a0e27; }
        .threat-high { background: #ff6600; color: #ffffff; }
        .threat-critical { background: #ff0066; color: #ffffff; animation: blink 1s infinite; }
        
        @keyframes blink {
            0%, 100% { opacity: 1; }
            50% { opacity: 0.7; }
        }
        
        .timeline {
            position: relative;
            padding-left: 30px;
        }
        
        .timeline-item {
            position: relative;
            padding-bottom: 20px;
        }
        
        .timeline-item::before {
            content: '';
            position: absolute;
            left: -22px;
            top: 5px;
            width: 10px;
            height: 10px;
            border-radius: 50%;
            background: #00ff41;
            box-shadow: 0 0 10px #00ff41;
        }
        
        .timeline-item::after {
            content: '';
            position: absolute;
            left: -18px;
            top: 15px;
            width: 2px;
            height: calc(100% - 10px);
            background: rgba(0, 255, 65, 0.3);
        }
        
        .timeline-item:last-child::after {
            display: none;
        }
        
        .timeline-time {
            color: #00d4ff;
            font-size: 0.9em;
            margin-bottom: 5px;
        }
        
        .timeline-content {
            color: #ffffff;
        }
        
        .code-block {
            background: #000000;
            border: 1px solid #00ff41;
            border-radius: 5px;
            padding: 15px;
            overflow-x: auto;
            font-family: 'Consolas', monospace;
            color: #00ff41;
        }
        
        .waiting-message {
            text-align: center;
            padding: 50px;
            color: #00d4ff;
            font-size: 1.2em;
            animation: pulse 2s infinite;
        }
        
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
            margin-bottom: 20px;
        }
        
        .stat-card {
            background: rgba(0, 212, 255, 0.1);
            border: 2px solid #00d4ff;
            border-radius: 8px;
            padding: 15px;
            text-align: center;
        }
        
        .stat-value {
            font-size: 2.5em;
            color: #00ff41;
            font-weight: bold;
            margin: 10px 0;
        }
        
        .stat-label {
            color: #00d4ff;
            font-size: 0.9em;
        }
        
        .progress-bar {
            width: 100%;
            height: 25px;
            background: rgba(0, 0, 0, 0.5);
            border-radius: 12px;
            overflow: hidden;
            margin: 10px 0;
        }
        
        .progress-fill {
            height: 100%;
            background: linear-gradient(90deg, #00ff41, #00d4ff);
            border-radius: 12px;
            transition: width 0.5s ease;
            display: flex;
            align-items: center;
            justify-content: center;
            color: #0a0e27;
            font-weight: bold;
        }
        
        .json-viewer {
            background: #000000;
            border: 1px solid #00ff41;
            border-radius: 5px;
            padding: 15px;
            max-height: 300px;
            overflow-y: auto;
            font-size: 0.9em;
        }
        
        .json-key {
            color: #00d4ff;
        }
        
        .json-string {
            color: #ffd700;
        }
        
        .json-number {
            color: #ff6600;
        }
        
        .json-boolean {
            color: #ff0066;
        }
        
        ::-webkit-scrollbar {
            width: 10px;
        }
        
        ::-webkit-scrollbar-track {
            background: rgba(0, 0, 0, 0.5);
            border-radius: 10px;
        }
        
        ::-webkit-scrollbar-thumb {
            background: #00ff41;
            border-radius: 10px;
        }
        
        ::-webkit-scrollbar-thumb:hover {
            background: #00d4ff;
        }
        
        /* Tab Navigation */
        .tab-nav {
            display: flex;
            gap: 10px;
            margin-bottom: 20px;
            background: rgba(0, 0, 0, 0.3);
            padding: 10px;
            border-radius: 8px;
            border: 1px solid rgba(0, 255, 65, 0.2);
        }
        
        .tab-btn {
            flex: 1;
            padding: 12px 20px;
            background: rgba(0, 212, 255, 0.1);
            border: 2px solid rgba(0, 212, 255, 0.3);
            border-radius: 6px;
            color: #00d4ff;
            cursor: pointer;
            font-size: 1em;
            font-weight: bold;
            transition: all 0.3s ease;
            font-family: 'Consolas', 'Monaco', monospace;
        }
        
        .tab-btn:hover {
            background: rgba(0, 212, 255, 0.2);
            border-color: #00d4ff;
            transform: translateY(-2px);
        }
        
        .tab-btn.active {
            background: rgba(0, 255, 65, 0.2);
            border-color: #00ff41;
            color: #00ff41;
            box-shadow: 0 0 15px rgba(0, 255, 65, 0.3);
        }
        
        .tab-content {
            display: none;
        }
        
        .tab-content.active {
            display: block;
            animation: fadeIn 0.3s ease-in;
        }
        
        @keyframes fadeIn {
            from { opacity: 0; transform: translateY(10px); }
            to { opacity: 1; transform: translateY(0); }
        }
        
        .attack-btn {
            padding: 20px;
            border: none;
            border-radius: 12px;
            color: white;
            cursor: pointer;
            transition: all 0.3s ease;
            font-family: 'Courier New', monospace;
            text-align: center;
        }
        
        .attack-btn:hover {
            transform: translateY(-5px);
            box-shadow: 0 10px 30px rgba(0, 212, 255, 0.3);
        }
        
        .attack-btn:active {
            transform: translateY(-2px);
        }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>🎯 AI HONEYPOT - LIVE DEMONSTRATION</h1>
            <p class="subtitle">
                <span class="status-indicator"></span>
                Real-Time Attack Analysis & Intelligence Processing
            </p>
        </header>
        
        <!-- Tab Navigation -->
        <div class="tab-nav">
            <button class="tab-btn active" onclick="switchTab('live-monitor')">📡 Live Monitor</button>
            <button class="tab-btn" onclick="switchTab('ai-intelligence')">🧠 AI Intelligence</button>
            <button class="tab-btn" onclick="switchTab('mitre-analysis')">🎯 MITRE Analysis</button>
            <button class="tab-btn" onclick="switchTab('threat-profile')">👤 Threat Profile</button>
            <button class="tab-btn" onclick="switchTab('attack-simulator')" style="color: #e74c3c;">⚡ Attack Simulator</button>
        </div>
        
        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-label">Total Attacks</div>
                <div class="stat-value" id="total-attacks">0</div>
            </div>
            <div class="stat-card">
                <div class="stat-label">Current Attacker</div>
                <div class="stat-value" id="current-attacker" style="font-size: 1.2em;">WAITING</div>
            </div>
            <div class="stat-card">
                <div class="stat-label">Threat Level</div>
                <div class="stat-value" id="threat-level">LOW</div>
            </div>
            <div class="stat-card">
                <div class="stat-label">Skill Level</div>
                <div class="stat-value" id="skill-level">-</div>
            </div>
        </div>
        
        <!-- TAB 1: Live Monitor -->
        <div id="live-monitor" class="tab-content active">
            <div class="main-grid">
                <!-- Current Attack -->
                <div class="panel full-width">
                    <h2>🎯 INCOMING ATTACK</h2>
                    <div id="current-attack">
                        <div class="waiting-message">
                            Waiting for attack...
                        </div>
                    </div>
                </div>
                
                <!-- Attack Timeline -->
                <div class="panel full-width">
                    <h2>📊 ATTACK TIMELINE</h2>
                    <div class="timeline" id="attack-timeline">
                        <div class="waiting-message">
                            Attack history will appear here...
                        </div>
                    </div>
                </div>
            </div>
        </div>
        
        <!-- TAB 2: AI Intelligence -->
        <div id="ai-intelligence" class="tab-content">
            <div class="main-grid">
                <!-- LLM Thinking Process -->
                <div class="panel full-width">
                    <h2>🧠 LLM REASONING PROCESS</h2>
                    <div id="llm-thinking">
                        <div class="waiting-message">
                            LLM analysis will appear here...
                        </div>
                    </div>
                </div>
                
                <!-- AI Prediction Engine -->
                <div class="panel full-width">
                    <h2>🔮 NEXT ATTACK PREDICTION</h2>
                    <div id="prediction-display">
                        <div class="waiting-message">
                            Prediction data will appear after first attack...
                        </div>
                    </div>
                </div>
            </div>
        </div>
        
        <!-- TAB 3: MITRE Analysis -->
        <div id="mitre-analysis" class="tab-content">
            <div class="main-grid">
                <!-- MITRE ATT&CK Mapping -->
                <div class="panel full-width">
                    <h2>🎯 MITRE ATT&CK TECHNIQUES</h2>
                    <div id="mitre-display">
                        <div class="waiting-message">
                            MITRE mapping will appear after first attack...
                        </div>
                    </div>
                </div>
            </div>
        </div>
        
        <!-- TAB 4: Threat Profile -->
        <div id="threat-profile" class="tab-content">
            <div class="main-grid">
                <!-- Behavioral Profile -->
                <div class="panel">
                    <h2>👤 ATTACKER PROFILE</h2>
                    <div id="behavioral-profile">
                        <div class="waiting-message">
                            Behavioral analysis will appear here...
                        </div>
                    </div>
                </div>
                
                <!-- Threat Intelligence -->
                <div class="panel">
                    <h2>⚠️ THREAT INTELLIGENCE</h2>
                    <div id="threat-intel">
                        <div class="waiting-message">
                            Threat data will appear here...
                        </div>
                    </div>
                </div>
                
                <!-- Intelligence Analysis -->
                <div class="panel full-width">
                    <h2>🔍 INTELLIGENCE ANALYSIS</h2>
                    <div id="intelligence-analysis">
                        <div class="waiting-message">
                            Intelligence data will appear here...
                    </div>
                </div>
            </div>
        </div>
        
        <!-- TAB 5: ATTACK SIMULATOR -->
        <div id="attack-simulator" class="tab-content">
            <div class="panel full-width">
                <h2>⚡ ATTACK SIMULATOR</h2>
                <p style="color: #888; margin-bottom: 20px;">Trigger simulated attacks to test the honeypot's detection and analysis capabilities.</p>
                
                <div style="display: grid; grid-template-columns: repeat(auto-fill, minmax(250px, 1fr)); gap: 15px;">
                    <button class="attack-btn" onclick="triggerAttack('sql')" style="background: linear-gradient(135deg, #e74c3c, #c0392b); border: 2px solid #e74c3c;">
                        <div style="font-size: 2em; margin-bottom: 10px;">💉</div>
                        <div style="font-size: 1.1em; font-weight: bold;">SQL Injection</div>
                        <div style="font-size: 0.85em; color: #ddd; margin-top: 5px;">Database exploitation</div>
                    </button>
                    
                    <button class="attack-btn" onclick="triggerAttack('xss')" style="background: linear-gradient(135deg, #e67e22, #d35400); border: 2px solid #e67e22;">
                        <div style="font-size: 2em; margin-bottom: 10px;">📜</div>
                        <div style="font-size: 1.1em; font-weight: bold;">XSS Attack</div>
                        <div style="font-size: 0.85em; color: #ddd; margin-top: 5px;">Cross-site scripting</div>
                    </button>
                    
                    <button class="attack-btn" onclick="triggerAttack('path')" style="background: linear-gradient(135deg, #f39c12, #e67e22); border: 2px solid #f39c12;">
                        <div style="font-size: 2em; margin-bottom: 10px;">📂</div>
                        <div style="font-size: 1.1em; font-weight: bold;">Path Traversal</div>
                        <div style="font-size: 0.85em; color: #ddd; margin-top: 5px;">File system access</div>
                    </button>
                    
                    <button class="attack-btn" onclick="triggerAttack('cmd')" style="background: linear-gradient(135deg, #9b59b6, #8e44ad); border: 2px solid #9b59b6;">
                        <div style="font-size: 2em; margin-bottom: 10px;">💻</div>
                        <div style="font-size: 1.1em; font-weight: bold;">Command Injection</div>
                        <div style="font-size: 0.85em; color: #ddd; margin-top: 5px;">Remote code execution</div>
                    </button>
                    
                    <button class="attack-btn" onclick="triggerAttack('ssrf')" style="background: linear-gradient(135deg, #3498db, #2980b9); border: 2px solid #3498db;">
                        <div style="font-size: 2em; margin-bottom: 10px;">☁️</div>
                        <div style="font-size: 1.1em; font-weight: bold;">SSRF</div>
                        <div style="font-size: 0.85em; color: #ddd; margin-top: 5px;">Server-side request forgery</div>
                    </button>
                    
                    <button class="attack-btn" onclick="triggerAttack('auth')" style="background: linear-gradient(135deg, #1abc9c, #16a085); border: 2px solid #1abc9c;">
                        <div style="font-size: 2em; margin-bottom: 10px;">🔓</div>
                        <div style="font-size: 1.1em; font-weight: bold;">Auth Bypass</div>
                        <div style="font-size: 0.85em; color: #ddd; margin-top: 5px;">Authentication bypass</div>
                    </button>
                    
                    <button class="attack-btn" onclick="triggerAttack('deser')" style="background: linear-gradient(135deg, #e74c3c, #c0392b); border: 2px solid #e74c3c;">
                        <div style="font-size: 2em; margin-bottom: 10px;">📦</div>
                        <div style="font-size: 1.1em; font-weight: bold;">Deserialization</div>
                        <div style="font-size: 0.85em; color: #ddd; margin-top: 5px;">Object injection</div>
                    </button>
                </div>
                
                <div id="sim-status" style="margin-top: 20px; padding: 15px; background: rgba(0, 0, 0, 0.3); border-radius: 8px; color: #00ff41; min-height: 50px; display: flex; align-items: center; justify-content: center;">
                    Ready to simulate attacks...
                </div>
            </div>
        </div>
    </div>
    
    <script>
        // Tab switching function
        function switchTab(tabId) {
            // Hide all tab contents
            document.querySelectorAll('.tab-content').forEach(content => {
                content.classList.remove('active');
            });
            
            // Remove active class from all buttons
            document.querySelectorAll('.tab-btn').forEach(btn => {
                btn.classList.remove('active');
            });
            
            // Show selected tab
            const selectedTab = document.getElementById(tabId);
            if (selectedTab) {
                selectedTab.classList.add('active');
            }
            
            // Activate corresponding button by finding it with the onclick attribute
            document.querySelectorAll('.tab-btn').forEach(btn => {
                if (btn.getAttribute('onclick') && btn.getAttribute('onclick').includes(`'${tabId}'`)) {
                    btn.classList.add('active');
                }
            });
        }
        
        const ws = new WebSocket('ws://localhost:8000/ws/demo');
        let attackCount = 0;
        let attackHistory = [];
        
        ws.onmessage = function(event) {
            const data = JSON.parse(event.data);
            
            if (data.type === 'attack') {
                handleAttack(data);
            } else if (data.type === 'llm_thinking') {
                updateLLMThinking(data.steps);
            } else if (data.type === 'intelligence') {
                updateIntelligence(data.analysis);
            } else if (data.type === 'behavioral') {
                updateBehavioral(data.profile);
            } else if (data.type === 'threat_intel') {
                updateThreatIntel(data.intel);
            } else if (data.type === 'prediction') {
                updatePrediction(data.data);
            } else if (data.type === 'mitre') {
                updateMITRE(data.data);
            }
        };
        
        function handleAttack(data) {
            attackCount++;
            attackHistory.unshift(data);
            if (attackHistory.length > 10) attackHistory.pop();
            
            // Update stats
            document.getElementById('total-attacks').textContent = attackCount;
            document.getElementById('current-attacker').textContent = data.attacker_id.substring(0, 8) + '...';
            document.getElementById('threat-level').textContent = data.threat_level || 'MEDIUM';
            document.getElementById('skill-level').textContent = data.skill_level || 'ANALYZING';
            
            // Update current attack display
            const attackHtml = `
                <div class="attack-display">
                    <div class="attack-label">⏰ Timestamp</div>
                    <div class="attack-value">${new Date(data.timestamp).toLocaleString()}</div>
                </div>
                <div class="attack-display">
                    <div class="attack-label">🎯 Attack Type</div>
                    <div class="attack-value">${data.attack_type}</div>
                </div>
                <div class="attack-display">
                    <div class="attack-label">🌐 IP Address</div>
                    <div class="attack-value">${data.ip}</div>
                </div>
                <div class="attack-display">
                    <div class="attack-label">📍 Endpoint</div>
                    <div class="attack-value">${data.endpoint}</div>
                </div>
                <div class="attack-display">
                    <div class="attack-label">💣 Payload</div>
                    <div class="code-block">${escapeHtml(data.payload)}</div>
                </div>
                <div class="attack-display">
                    <div class="attack-label">🔑 Attacker ID</div>
                    <div class="attack-value">${data.attacker_id}</div>
                </div>
            `;
            document.getElementById('current-attack').innerHTML = attackHtml;
            
            // Update timeline
            updateTimeline();
        }
        
        function updateLLMThinking(steps) {
            if (!steps || steps.length === 0) return;
            
            const html = steps.map((step, index) => `
                <div class="thinking-step">
                    <span class="step-number">Step ${index + 1}:</span>
                    <span class="step-content">${step}</span>
                </div>
            `).join('');
            
            document.getElementById('llm-thinking').innerHTML = html;
        }
        
        function updateIntelligence(analysis) {
            if (!analysis) return;
            
            const html = Object.entries(analysis).map(([key, value]) => `
                <div class="analysis-item">
                    <span class="analysis-label">${formatKey(key)}</span>
                    <span class="analysis-value">${value}</span>
                </div>
            `).join('');
            
            document.getElementById('intelligence-analysis').innerHTML = html;
        }
        
        function updateBehavioral(profile) {
            if (!profile) return;
            
            const html = `
                <div class="analysis-item">
                    <span class="analysis-label">Skill Level</span>
                    <span class="analysis-value">${profile.skill_level || 'Unknown'}</span>
                </div>
                <div class="analysis-item">
                    <span class="analysis-label">Tools Detected</span>
                    <span class="analysis-value">${(profile.tools || []).join(', ') || 'None'}</span>
                </div>
                <div class="analysis-item">
                    <span class="analysis-label">Attack Speed</span>
                    <span class="analysis-value">${profile.is_automated ? 'Automated' : 'Manual'}</span>
                </div>
                <div class="analysis-item">
                    <span class="analysis-label">Sophistication</span>
                    <div class="progress-bar">
                        <div class="progress-fill" style="width: ${profile.sophistication || 0}%">
                            ${profile.sophistication || 0}%
                        </div>
                    </div>
                </div>
                <div class="analysis-item">
                    <span class="analysis-label">Total Attacks</span>
                    <span class="analysis-value">${profile.attack_count || 0}</span>
                </div>
            `;
            
            document.getElementById('behavioral-profile').innerHTML = html;
        }
        
        function updateThreatIntel(intel) {
            if (!intel) return;
            
            const threatClass = intel.threat_score > 80 ? 'threat-critical' :
                               intel.threat_score > 60 ? 'threat-high' :
                               intel.threat_score > 30 ? 'threat-medium' : 'threat-low';
            
            const html = `
                <div class="analysis-item">
                    <span class="analysis-label">Threat Score</span>
                    <span class="analysis-value">
                        <span class="threat-badge ${threatClass}">${intel.threat_score}/100</span>
                    </span>
                </div>
                <div class="analysis-item">
                    <span class="analysis-label">IP Reputation</span>
                    <span class="analysis-value">${intel.reputation || 'Unknown'}</span>
                </div>
                <div class="analysis-item">
                    <span class="analysis-label">Country</span>
                    <span class="analysis-value">${intel.country || 'Unknown'}</span>
                </div>
                <div class="analysis-item">
                    <span class="analysis-label">Known Malicious</span>
                    <span class="analysis-value">${intel.is_malicious ? 'YES ⚠️' : 'NO ✓'}</span>
                </div>
                ${intel.sources ? `
                <div class="analysis-item">
                    <span class="analysis-label">Intel Sources</span>
                    <span class="analysis-value">${intel.sources.join(', ')}</span>
                </div>
                ` : ''}
            `;
            
            document.getElementById('threat-intel').innerHTML = html;
        }
        
        function updatePrediction(data) {
            if (!data || !data.predictions) return;
            
            const predictions = data.predictions.slice(0, 3); // Top 3 predictions
            
            // Build reasoning steps display
            let reasoningHtml = '';
            if (data.reasoning_steps && data.reasoning_steps.length > 0) {
                reasoningHtml = `
                    <h3 style="color: #00ff41; margin: 20px 0 15px 0; border-bottom: 2px solid #00ff41; padding-bottom: 8px;">
                        🧠 LLM REASONING PROCESS
                    </h3>
                    <div style="background: rgba(0, 0, 0, 0.3); border-left: 4px solid #00ff41; padding: 15px; border-radius: 4px; margin-bottom: 20px;">
                        ${data.reasoning_steps.map((step, index) => {
                            // Parse markdown-style bold text
                            const formattedStep = step.replace(/\*\*(.*?)\*\*/g, '<strong style="color: #00d4ff;">$1</strong>');
                            return `
                                <div style="margin-bottom: 12px; padding: 10px; background: rgba(0, 212, 255, 0.05); border-radius: 4px;">
                                    <div style="color: #00ff41; font-size: 0.95em; line-height: 1.6;">
                                        ${formattedStep}
                                    </div>
                                </div>
                            `;
                        }).join('')}
                    </div>
                `;
            }
            
            const html = `
                ${reasoningHtml}
                
                <h3 style="color: #00d4ff; margin: 20px 0 15px 0; border-bottom: 2px solid #00d4ff; padding-bottom: 8px;">
                    🔮 PREDICTION RESULTS
                </h3>
                
                <div class="analysis-item" style="background: rgba(0, 212, 255, 0.1); border: 2px solid #00d4ff; padding: 15px; border-radius: 8px; margin-bottom: 15px;">
                    <h3 style="color: #00ff41; margin: 0 0 10px 0;">Most Likely Next Attack</h3>
                    <div style="font-size: 1.5em; color: #ffffff; font-weight: bold;">${predictions[0].attack}</div>
                    <div style="color: #00d4ff; font-size: 1.2em; margin-top: 5px;">Probability: ${predictions[0].probability}</div>
                </div>
                
                <div class="analysis-item">
                    <span class="analysis-label">Confidence Level</span>
                    <span class="analysis-value">${data.confidence}</span>
                </div>
                
                <div class="analysis-item">
                    <span class="analysis-label">Based On</span>
                    <span class="analysis-value">${data.last_attack}</span>
                </div>
                
                ${data.attack_count ? `
                <div class="analysis-item">
                    <span class="analysis-label">Attack History</span>
                    <span class="analysis-value">${data.attack_count} attack(s) analyzed</span>
                </div>
                ` : ''}
                
                <h3 style="color: #00d4ff; margin: 20px 0 10px 0; border-bottom: 1px solid #00d4ff; padding-bottom: 5px;">Alternative Scenarios</h3>
                ${predictions.slice(1).map(pred => `
                    <div class="analysis-item">
                        <span class="analysis-label">${pred.attack}</span>
                        <div style="flex: 1; margin: 0 10px;">
                            <div style="background: rgba(0, 0, 0, 0.3); border-radius: 10px; overflow: hidden; height: 20px;">
                                <div style="background: linear-gradient(90deg, #00d4ff, #00ff41); height: 100%; width: ${pred.probability}; border-radius: 10px; transition: width 0.5s ease;"></div>
                            </div>
                        </div>
                        <span class="analysis-value">${pred.probability}</span>
                    </div>
                `).join('')}
            `;
            
            document.getElementById('prediction-display').innerHTML = html;
        }
        
        function updateMITRE(data) {
            if (!data || !data.techniques || data.techniques.length === 0) return;
            
            const html = `
                <div style="margin-bottom: 20px;">
                    <div class="analysis-item">
                        <span class="analysis-label">Techniques Detected</span>
                        <span class="analysis-value">${data.techniques.length}</span>
                    </div>
                    <div class="analysis-item">
                        <span class="analysis-label">Tactics Covered</span>
                        <span class="analysis-value">${data.tactics_covered.join(', ')}</span>
                    </div>
                    ${data.apt_groups && data.apt_groups.length > 0 ? `
                    <div class="analysis-item">
                        <span class="analysis-label">Potential APT Groups</span>
                        <span class="analysis-value" style="color: #e74c3c;">${data.apt_groups.join(', ')}</span>
                    </div>
                    ` : ''}
                </div>
                
                <h3 style="color: #00d4ff; margin: 20px 0 10px 0; border-bottom: 1px solid #00d4ff; padding-bottom: 5px;">ATT&CK Techniques</h3>
                <div style="display: grid; grid-template-columns: repeat(auto-fill, minmax(300px, 1fr)); gap: 15px;">
                    ${data.techniques.map(tech => `
                        <div style="background: rgba(0, 212, 255, 0.1); border: 1px solid #00d4ff; border-radius: 8px; padding: 15px;">
                            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 10px;">
                                <span style="background: #00d4ff; color: #0a0e27; padding: 4px 8px; border-radius: 4px; font-weight: bold; font-size: 0.9em;">${tech.id}</span>
                                <span style="background: rgba(0, 255, 65, 0.2); color: #00ff41; padding: 4px 8px; border-radius: 4px; font-size: 0.85em;">${tech.tactic}</span>
                            </div>
                            <div style="color: #ffffff; font-weight: bold; margin-bottom: 5px;">${tech.technique}</div>
                            <div style="color: #888; font-size: 0.85em;">Detected: ${new Date(tech.detected_at).toLocaleTimeString()}</div>
                        </div>
                    `).join('')}
                </div>
            `;
            
            document.getElementById('mitre-display').innerHTML = html;
        }
        
        function updateTimeline() {
            const html = attackHistory.map(attack => `
                <div class="timeline-item">
                    <div class="timeline-time">${new Date(attack.timestamp).toLocaleTimeString()}</div>
                    <div class="timeline-content">
                        <strong>${attack.attack_type}</strong> from ${attack.ip}
                        <br>
                        <code>${attack.payload.substring(0, 50)}${attack.payload.length > 50 ? '...' : ''}</code>
                    </div>
                </div>
            `).join('');
            
            document.getElementById('attack-timeline').innerHTML = html || '<div class="waiting-message">No attacks yet...</div>';
        }
        
        function formatKey(key) {
            return key.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase());
        }
        
        function escapeHtml(text) {
            const div = document.createElement('div');
            div.textContent = text;
            return div.innerHTML;
        }
        
        // Attack simulator function
        async function triggerAttack(attackType) {
            const status = document.getElementById('sim-status');
            const attackMap = {
                'sql': { url: '/search?q=%27%20OR%201=1--', name: 'SQL Injection' },
                'xss': { url: '/search?q=%3Cscript%3Ealert(%27XSS%27)%3C/script%3E', name: 'XSS Attack' },
                'path': { url: '/files?path=../../../../etc/passwd', name: 'Path Traversal' },
                'cmd': { url: '/admin?cmd=cat%20/etc/shadow', name: 'Command Injection' },
                'ssrf': { url: '/api/fetch?url=http://169.254.169.254/latest/meta-data/', name: 'SSRF' },
                'auth': { url: '/admin?user=admin&sess=adm_123', name: 'Auth Bypass' },
                'deser': { url: '/api/data?obj=rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcA', name: 'Deserialization' }
            };
            
            const attack = attackMap[attackType];
            if (!attack) {
                status.innerHTML = '❌ Unknown attack type';
                status.style.color = '#e74c3c';
                return;
            }
            
            status.innerHTML = `⏳ Launching ${attack.name}...`;
            status.style.color = '#f39c12';
            
            try {
                const response = await fetch(attack.url);
                status.innerHTML = `✅ ${attack.name} triggered! Check the Live Monitor tab for results.`;
                status.style.color = '#00ff41';
                
                // Auto-switch to Live Monitor tab after 1 second
                setTimeout(() => {
                    switchTab('live-monitor');
                }, 1000);
            } catch (error) {
                status.innerHTML = `❌ Error: ${error.message}`;
                status.style.color = '#e74c3c';
            }
        }
        
        ws.onopen = function() {
            console.log('Connected to demonstration dashboard');
        };
        
        ws.onmessage = function(event) {
            const data = JSON.parse(event.data);
            console.log('Received attack data:', data);
            
            if (data.type === 'attack') {
                // Update attack counter
                const totalAttacksEl = document.getElementById('total-attacks');
                if (totalAttacksEl) {
                    const currentCount = parseInt(totalAttacksEl.textContent) || 0;
                    totalAttacksEl.textContent = currentCount + 1;
                }
                
                // Update current attacker
                const currentAttackerEl = document.getElementById('current-attacker');
                if (currentAttackerEl && data.attacker_id) {
                    currentAttackerEl.textContent = data.attacker_id.substring(0, 8) + '...';
                }
                
                // Update threat level
                const threatLevelEl = document.getElementById('threat-level');
                if (threatLevelEl && data.threat_level) {
                    threatLevelEl.textContent = data.threat_level;
                }
                
                // Update skill level
                const skillLevelEl = document.getElementById('skill-level');
                if (skillLevelEl && data.skill_level) {
                    skillLevelEl.textContent = data.skill_level;
                }
                
                // Update current attack display in Live Monitor tab
                const currentAttackEl = document.getElementById('current-attack');
                if (currentAttackEl) {
                    currentAttackEl.innerHTML = `
                        <div style="padding: 20px; background: rgba(231, 76, 60, 0.1); border: 2px solid #e74c3c; border-radius: 8px;">
                            <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 15px; margin-bottom: 15px;">
                                <div>
                                    <div style="color: #aaa; font-size: 0.9em;">Attack Type</div>
                                    <div style="color: #e74c3c; font-size: 1.3em; font-weight: bold;">${data.attack_type || 'Unknown'}</div>
                                </div>
                                <div>
                                    <div style="color: #aaa; font-size: 0.9em;">Source IP</div>
                                    <div style="color: #00d4ff; font-size: 1.1em;">${data.ip || 'Unknown'}</div>
                                </div>
                            </div>
                            <div style="margin-bottom: 10px;">
                                <div style="color: #aaa; font-size: 0.9em; margin-bottom: 5px;">Payload</div>
                                <div style="color: #00ff41; font-family: monospace; background: rgba(0,0,0,0.3); padding: 10px; border-radius: 5px; word-break: break-all;">${data.payload || 'N/A'}</div>
                            </div>
                            <div style="color: #aaa; font-size: 0.85em;">
                                Detected at: ${new Date().toLocaleTimeString()}
                            </div>
                        </div>
                    `;
                }
                
                // Update LLM Thinking if available
                if (data.llm_reasoning && data.llm_reasoning.length > 0) {
                    const llmThinkingEl = document.getElementById('llm-thinking');
                    if (llmThinkingEl) {
                        llmThinkingEl.innerHTML = '';
                        data.llm_reasoning.forEach(step => {
                            const stepDiv = document.createElement('div');
                            stepDiv.style.cssText = 'margin-bottom: 15px; padding: 15px; background: rgba(0, 212, 255, 0.1); border-left: 3px solid #00d4ff; border-radius: 5px;';
                            stepDiv.innerHTML = `
                                <div style="color: #00d4ff; font-weight: bold; margin-bottom: 5px;">Step ${step.step}: ${step.title}</div>
                                <div style="color: #aaa; margin-bottom: 5px;">${step.description}</div>
                                <div style="color: #00ff41;">→ ${step.result}</div>
                            `;
                            llmThinkingEl.appendChild(stepDiv);
                        });
                    }
                }
                
                // Update Prediction if available
                if (data.prediction && data.prediction.next_likely_vectors && data.prediction.next_likely_vectors.length > 0) {
                    const predictionDisplayEl = document.getElementById('prediction-display');
                    if (predictionDisplayEl) {
                        const topPrediction = data.prediction.next_likely_vectors[0];
                        predictionDisplayEl.innerHTML = `
                            <div style="padding: 20px; background: rgba(0, 212, 255, 0.1); border: 2px solid #00d4ff; border-radius: 8px;">
                                <h3 style="color: #00ff41; margin: 0 0 10px 0;">Most Likely Next Attack</h3>
                                <div style="font-size: 1.5em; color: #ffffff; font-weight: bold; margin-bottom: 10px;">${topPrediction.vector || 'Unknown'}</div>
                                <div style="color: #00d4ff; font-size: 1.2em;">Probability: ${topPrediction.probability || 'N/A'}</div>
                                <div style="color: #aaa; margin-top: 10px; font-size: 0.9em;">Current Stage: ${data.prediction.current_stage || 'Unknown'}</div>
                                <div style="color: #aaa; font-size: 0.9em;">Predicted Goal: ${data.prediction.predicted_goal || 'Unknown'}</div>
                            </div>
                        `;
                    }
                } else if (data.prediction && !data.prediction.error) {
                    const predictionDisplayEl = document.getElementById('prediction-display');
                    if (predictionDisplayEl) {
                        predictionDisplayEl.innerHTML = `
                            <div style="padding: 15px; background: rgba(0, 0, 0, 0.3); border-radius: 8px; color: #aaa;">
                                Building prediction model... More data needed.
                            </div>
                        `;
                    }
                }
                
                // Update MITRE if available
                console.log('MITRE data:', data.mitre);
                if (data.mitre && data.mitre.techniques && data.mitre.techniques.length > 0) {
                    const mitreDisplayEl = document.getElementById('mitre-display');
                    if (mitreDisplayEl) {
                        mitreDisplayEl.innerHTML = '';
                        data.mitre.techniques.slice(0, 5).forEach(technique => {
                            const techDiv = document.createElement('div');
                            techDiv.style.cssText = 'margin-bottom: 10px; padding: 12px; background: rgba(0, 0, 0, 0.3); border-left: 3px solid #e74c3c; border-radius: 5px;';
                            techDiv.innerHTML = `
                                <div style="color: #e74c3c; font-weight: bold;">${technique.technique_id}</div>
                                <div style="color: #fff; margin: 5px 0;">${technique.technique_name}</div>
                                <div style="color: #aaa; font-size: 0.9em;">${technique.tactic}</div>
                            `;
                            mitreDisplayEl.appendChild(techDiv);
                        });
                    }
                } else if (data.mitre) {
                    // Show message if MITRE data exists but no techniques
                    const mitreDisplayEl = document.getElementById('mitre-display');
                    if (mitreDisplayEl) {
                        mitreDisplayEl.innerHTML = `
                            <div style="padding: 15px; background: rgba(0, 0, 0, 0.3); border-radius: 8px; color: #aaa;">
                                Building MITRE ATT&CK mapping... Attack type: ${data.attack_type || 'Unknown'}
                            </div>
                        `;
                    }
                }
                
                // Update Behavioral Profile if available
                if (data.behavioral_profile) {
                    const behavioralProfileEl = document.getElementById('behavioral-profile');
                    if (behavioralProfileEl) {
                        const bp = data.behavioral_profile;
                        behavioralProfileEl.innerHTML = `
                            <div style="padding: 15px; background: rgba(0, 0, 0, 0.3); border-radius: 8px;">
                                <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 15px; margin-bottom: 15px;">
                                    <div>
                                        <div style="color: #aaa; font-size: 0.9em;">Skill Level</div>
                                        <div style="color: #00ff41; font-size: 1.2em; font-weight: bold;">${bp.skill_level || 'UNKNOWN'}</div>
                                    </div>
                                    <div>
                                        <div style="color: #aaa; font-size: 0.9em;">Attack Count</div>
                                        <div style="color: #00d4ff; font-size: 1.2em; font-weight: bold;">${bp.attack_count || 0}</div>
                                    </div>
                                </div>
                                <div style="margin-bottom: 10px;">
                                    <div style="color: #aaa; font-size: 0.9em; margin-bottom: 5px;">Attack Types</div>
                                    <div style="color: #fff;">${(bp.attack_types || []).join(', ') || 'N/A'}</div>
                                </div>
                                <div style="color: #aaa; font-size: 0.85em;">
                                    First Seen: ${new Date(bp.first_seen).toLocaleString()}
                                </div>
                            </div>
                        `;
                    }
                }
                
                // Update Threat Intelligence if available
                if (data.threat_intelligence) {
                    const threatIntelEl = document.getElementById('threat-intel');
                    if (threatIntelEl) {
                        const ti = data.threat_intelligence;
                        threatIntelEl.innerHTML = `
                            <div style="padding: 15px; background: rgba(231, 76, 60, 0.1); border: 2px solid #e74c3c; border-radius: 8px;">
                                <div style="margin-bottom: 15px;">
                                    <div style="color: #aaa; font-size: 0.9em;">Threat Level</div>
                                    <div style="color: #e74c3c; font-size: 1.3em; font-weight: bold;">${ti.threat_level || 'MEDIUM'}</div>
                                </div>
                                <div style="margin-bottom: 15px;">
                                    <div style="color: #aaa; font-size: 0.9em; margin-bottom: 5px;">Risk Score</div>
                                    <div style="background: rgba(0,0,0,0.3); border-radius: 10px; overflow: hidden; height: 20px;">
                                        <div style="background: linear-gradient(90deg, #00ff41, #e74c3c); height: 100%; width: ${ti.risk_score || 50}%; border-radius: 10px;"></div>
                                    </div>
                                    <div style="color: #00d4ff; margin-top: 5px;">${ti.risk_score || 50}/100</div>
                                </div>
                                <div style="color: ${ti.is_persistent ? '#e74c3c' : '#00ff41'}; font-weight: bold;">
                                    ${ti.is_persistent ? '⚠️ Persistent Threat' : '✓ Non-Persistent'}
                                </div>
                            </div>
                        `;
                    }
                }
                
                // Update Intelligence Analysis
                const intelligenceAnalysisEl = document.getElementById('intelligence-analysis');
                if (intelligenceAnalysisEl) {
                    intelligenceAnalysisEl.innerHTML = `
                        <div style="padding: 15px; background: rgba(0, 0, 0, 0.3); border-radius: 8px;">
                            <div style="color: #00d4ff; font-size: 1.1em; margin-bottom: 10px;">Attack Summary</div>
                            <div style="color: #fff; margin-bottom: 15px;">
                                Detected ${data.attack_type || 'Unknown'} attack from ${data.ip || 'Unknown IP'} targeting ${data.endpoint || '/search'} endpoint.
                            </div>
                            <div style="color: #00d4ff; font-size: 1.1em; margin-bottom: 10px;">Assessment</div>
                            <div style="color: #fff;">
                                Attacker demonstrates ${data.skill_level || 'UNKNOWN'} skill level with ${data.threat_level || 'MEDIUM'} threat rating. 
                                ${data.prediction && data.prediction.next_likely_vectors && data.prediction.next_likely_vectors.length > 0 ? 
                                  'Predicted next attack: ' + data.prediction.next_likely_vectors[0].vector : 
                                  'Monitoring for follow-up attacks.'}
                            </div>
                        </div>
                    `;
                }
                
                // Update Attack Timeline
                const attackTimelineEl = document.getElementById('attack-timeline');
                if (attackTimelineEl) {
                    const timelineItem = document.createElement('div');
                    timelineItem.style.cssText = 'padding: 12px; background: rgba(0, 212, 255, 0.1); border-left: 3px solid #00d4ff; border-radius: 5px; margin-bottom: 10px;';
                    timelineItem.innerHTML = `
                        <div style="color: #00d4ff; font-weight: bold; margin-bottom: 5px;">${new Date().toLocaleTimeString()} - ${data.attack_type || 'Unknown Attack'}</div>
                        <div style="color: #aaa; font-size: 0.9em;">From: ${data.ip || 'Unknown'}</div>
                        <div style="color: #fff; font-family: monospace; font-size: 0.85em; margin-top: 5px;">${data.payload || 'N/A'}</div>
                    `;
                    // Remove "waiting" message if it exists
                    const waitingMsg = attackTimelineEl.querySelector('.waiting-message');
                    if (waitingMsg) {
                        waitingMsg.remove();
                    }
                    // Add new item at the top
                    attackTimelineEl.insertBefore(timelineItem, attackTimelineEl.firstChild);
                }
            }
        };
        
        ws.onerror = function(error) {
            console.error('WebSocket error:', error);
        };
    </script>
</body>
</html>
"""


def update_demo_attack(attack_data: Dict[str, Any]) -> None:
    """Update demonstration dashboard with new attack."""
    _demo_data["current_attack"] = attack_data


def update_demo_llm_thinking(steps: List[str]) -> None:
    """Update LLM thinking steps."""
    _demo_data["llm_thinking"] = steps


def update_demo_analysis(analysis: Dict[str, Any]) -> None:
    """Update intelligence analysis."""
    _demo_data["analysis_steps"] = analysis


def update_demo_threat_intel(intel: Dict[str, Any]) -> None:
    """Update threat intelligence data."""
    _demo_data["threat_intel"] = intel


def update_demo_behavioral(profile: Dict[str, Any]) -> None:
    """Update behavioral profile."""
    _demo_data["behavioral_profile"] = profile


def get_demo_data() -> Dict[str, Any]:
    """Get all demonstration data."""
    return _demo_data
