# 🎯 AI Honeypot - Live Demo Script

**Quick Reference Guide for Hackathon Presentation**

---

## 🚀 Pre-Demo Setup (5 minutes before)

### 1. Start the Honeypot
```bash
cd C:\Users\rajde\Desktop\Honeypot\ai-honepot
python app.py
```
✅ Wait for: "Uvicorn running on http://127.0.0.1:8000"

### 2. Open Dashboard
```
http://localhost:8000/demo
```
✅ Verify: Dashboard loads, shows 0 attacks

### 3. Prepare Browser Tabs
- Tab 1: Dashboard (http://localhost:8000/demo)
- Tab 2: Attack URLs (ready to launch)
- Tab 3: DevTools (F12 → Application → Cookies)

---

## 📢 Opening Pitch (30 seconds)

> "We built an AI-powered honeypot that **predicts attacker behavior** using machine learning. It detects **7 different OWASP vulnerability types** - that's **70% coverage of the OWASP Top 10**. Every attack is automatically mapped to **MITRE ATT&CK**, and we generate **incident response playbooks** instantly. Watch as I demonstrate..."

---

## 🎬 Live Demo Flow (5-7 minutes)

### **STEP 1: Show Clean Dashboard (15 seconds)**

**What to show:**
- Point to attack counter: "Currently 0 attacks"
- Point to threat level: "System is calm"

**Say:**
> "This is our real-time dashboard. Right now, the honeypot is idle. Let me launch some attacks..."

---

### **STEP 2: Launch SQL Injection (30 seconds)**

**Attack URL:**
```
http://localhost:8000/search?q=' OR 1=1--
```

**What to show:**
- Dashboard updates instantly
- Attack counter increments
- Attack type shows "SQL Injection"
- Threat level appears

**Say:**
> "I just launched a SQL injection attack. Notice the dashboard updated in real-time via WebSockets. The system detected it as SQL Injection and assigned a threat level."

---

### **STEP 3: Launch XSS Attack (30 seconds)**

**Attack URL:**
```
http://localhost:8000/search?q=<script>alert('XSS')</script>
```

**What to show:**
- Attack counter: now 2
- Different attack type displayed
- Timeline building

**Say:**
> "Now an XSS attack. The system tracks different attack types and builds a timeline of the attacker's behavior."

---

### **STEP 4: Escalate to Privilege Escalation (45 seconds)**

**Attack URL:**
```
http://localhost:8000/search?q=' UNION SELECT * FROM users--
```

**What to show:**
- Threat level increasing
- Attack counter: 3+

**Say:**
> "Watch the threat level. As I escalate to privilege escalation attempts, the AI predicts this is getting serious. The threat level is now climbing to HIGH or CRITICAL."

---

### **STEP 5: Show Attack Prediction (60 seconds)**

**Get Attacker ID:**
1. Press F12 (DevTools)
2. Application → Cookies → Copy `attacker_id`

**Prediction URL:**
```
http://localhost:8000/api/prediction/{YOUR_ATTACKER_ID}
```

**What to show:**
```json
{
  "current_stage": "privilege_escalation",
  "predicted_goal": "system_compromise",
  "threat_level": "high",
  "next_likely_vectors": [
    {"vector": "admin_access", "probability": "60%"}
  ],
  "time_to_compromise_minutes": 10
}
```

**Say:**
> "Here's where the AI shines. Based on the attack sequence, it predicts:
> - Current stage: Privilege escalation
> - Goal: System compromise  
> - Next attack: 60% probability of admin access
> - Time to compromise: 10 minutes
> 
> This is **machine learning in action** - predicting the attacker's next move."

---

### **STEP 6: Show MITRE ATT&CK Mapping (45 seconds)**

**MITRE URL:**
```
http://localhost:8000/api/mitre/{YOUR_ATTACKER_ID}
```

**What to show:**
```json
{
  "tactics": ["Initial Access", "Execution"],
  "techniques": [
    {
      "id": "T1190",
      "name": "Exploit Public-Facing Application",
      "tactic": "Initial Access"
    }
  ],
  "similar_apt_groups": ["APT28", "Lazarus Group"]
}
```

**Say:**
> "Every attack is automatically mapped to the **MITRE ATT&CK framework** - the industry standard for threat intelligence. This attack matches tactics used by APT groups like APT28."

---

### **STEP 7: Show Auto-Generated Playbook (45 seconds)**

**Playbook URL:**
```
http://localhost:8000/api/playbook/SQL%20Injection
```

**What to show:**
- Markdown file downloads
- Open it to show:
  - Containment steps
  - Investigation procedures
  - Remediation actions
  - Sigma rules for SIEM

**Say:**
> "The system automatically generates **incident response playbooks**. This is a complete runbook with containment, investigation, and remediation steps. It even includes Sigma rules for your SIEM. This saves security teams hours of work."

---

### **STEP 8: Show Timeline & Narrative (30 seconds)**

**Timeline URL:**
```
http://localhost:8000/api/timeline/{YOUR_ATTACKER_ID}
```

**Narrative URL:**
```
http://localhost:8000/api/timeline/{YOUR_ATTACKER_ID}/narrative
```

**What to show:**
- Complete attack timeline
- Human-readable narrative

**Say:**
> "We also generate a complete attack timeline and a human-readable narrative. This is perfect for incident reports and forensic analysis."

---

## 🎯 Closing Statement (30 seconds)

> "To summarize what you just saw:
> - **Real-time detection** of 7 OWASP vulnerability types
> - **AI-powered prediction** of the attacker's next move
> - **Automatic MITRE ATT&CK mapping** for threat intelligence
> - **Auto-generated playbooks** for instant incident response
> - **100% test success rate** - all 10 API endpoints working
> - **Production-ready** with Docker deployment
> 
> This isn't just a hackathon project - it's a tool security teams can actually use. Thank you!"

---

## 🔥 Backup Demo (If Time Permits)

### Show STIX Export
```
http://localhost:8000/api/threat-intel/{YOUR_ATTACKER_ID}/stix
```

**Say:**
> "We also export to STIX 2.1 format for threat intelligence sharing with other organizations."

### Show CSV Export
```
http://localhost:8000/api/export/attacks
```

**Say:**
> "All attacks can be exported to CSV for analysis in Excel or your SIEM."

---

## 📋 Quick Reference URLs

**Replace `{ID}` with your attacker_id from cookies**

```
Dashboard:     http://localhost:8000/demo
Prediction:    http://localhost:8000/api/prediction/{ID}
MITRE:         http://localhost:8000/api/mitre/{ID}
Timeline:      http://localhost:8000/api/timeline/{ID}
Narrative:     http://localhost:8000/api/timeline/{ID}/narrative
Playbook:      http://localhost:8000/api/playbook/SQL%20Injection
STIX:          http://localhost:8000/api/threat-intel/{ID}/stix
CSV Export:    http://localhost:8000/api/export/attacks
```

---

## 🚨 Attack URLs (Copy-Paste Ready)

```
# SQL Injection
http://localhost:8000/search?q=' OR 1=1--

# XSS
http://localhost:8000/search?q=<script>alert('XSS')</script>

# Privilege Escalation
http://localhost:8000/search?q=' UNION SELECT * FROM users--

# Path Traversal
http://localhost:8000/search?q=../../../etc/passwd

# Command Injection
http://localhost:8000/search?q=; ls -la

# SSRF
http://localhost:8000/search?q=http://localhost:8080/admin

# Auth Bypass
http://localhost:8000/login?user=admin:admin
```

---

## 💡 Key Talking Points

✅ **"7 out of 10 OWASP Top 10 vulnerabilities"** - 70% coverage  
✅ **"Machine learning predicts next attack"** - Unique feature  
✅ **"MITRE ATT&CK integration"** - Industry standard  
✅ **"Auto-generated playbooks"** - Saves time  
✅ **"100% test success"** - Production ready  
✅ **"Real-time WebSocket updates"** - Modern tech  

---

## ⚠️ Troubleshooting

**Dashboard not updating?**
- Refresh the page
- Check WebSocket connection in DevTools → Network → WS

**Can't find attacker_id?**
- F12 → Application → Cookies → Look for `attacker_id`
- Or check `attacks.json` file

**API returns empty?**
- Make sure you launched at least 1 attack
- Verify attacker_id is correct

---

## 🎓 Judge Q&A - Quick Answers

**Q: "What makes this unique?"**
> "Three things: ML-based attack prediction, automatic MITRE mapping, and auto-generated playbooks. Traditional honeypots just log - we predict and respond."

**Q: "Is it production-ready?"**
> "Yes. Docker deployment, 10/10 API endpoints tested, comprehensive logging, and SIEM integration via STIX export."

**Q: "How does the ML work?"**
> "Markov chains. We track attack sequences and build probability matrices. For example, after SQL injection, there's a 60% probability of admin access next."

**Q: "What's your OWASP coverage?"**
> "7 out of 10 - 70% coverage. We focus on attack-oriented vulnerabilities that honeypots actually encounter in the wild."

---

**GOOD LUCK! 🏆**

**Remember:** Speak confidently, show the features, and emphasize the AI prediction - that's your differentiator!
