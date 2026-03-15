# 🚨 Threat Level Examples - When Does It Become HIGH?

## Understanding Threat Levels

The honeypot calculates threat levels based on **two systems**:

1. **IP-based Threat Level** (`threat_intel.py`)
2. **Attack Prediction Threat Level** (`attack_predictor.py`)

---

## System 1: IP-Based Threat Levels

**File:** `threat_intel.py` (Lines 67-76)

### Calculation Logic

```python
def calculate_threat_level(self) -> ThreatLevel:
    """Calculate overall threat level."""
    if self.abuse_score > 75 or self.reputation == IPReputation.MALICIOUS:
        return ThreatLevel.CRITICAL
    elif self.abuse_score > 50 or self.reputation == IPReputation.SUSPICIOUS:
        return ThreatLevel.HIGH
    elif self.is_vpn or self.is_proxy or self.is_tor:
        return ThreatLevel.MEDIUM
    else:
        return ThreatLevel.LOW
```

### When Threat Level Becomes HIGH

✅ **Abuse Score > 50** - IP has moderate malicious activity  
✅ **Reputation = SUSPICIOUS** - IP flagged as suspicious  

### When Threat Level Becomes CRITICAL

🔴 **Abuse Score > 75** - IP has high malicious activity  
🔴 **Reputation = MALICIOUS** - IP confirmed malicious  

### Example Scenarios

#### Example 1: HIGH Threat (Abuse Score = 60)
```
IP: 203.0.113.45
Abuse Score: 60
Reputation: SUSPICIOUS
Is VPN: No
Is Tor: No

→ Threat Level: HIGH
```

#### Example 2: CRITICAL Threat (Malicious IP)
```
IP: 198.51.100.99
Abuse Score: 85
Reputation: MALICIOUS
Is VPN: No
Is Tor: No

→ Threat Level: CRITICAL
```

#### Example 3: MEDIUM Threat (Tor Exit Node)
```
IP: 192.0.2.100
Abuse Score: 50
Reputation: TOR
Is VPN: No
Is Tor: Yes

→ Threat Level: MEDIUM (Tor detected)
```

---

## System 2: Attack Prediction Threat Levels

**File:** `attack_predictor.py` (Lines 485-529)

### Calculation Logic

Threat level is calculated using a **scoring system**:

```python
def _calculate_threat_level(
    stage: AttackStage,
    goal: AttackGoal,
    skill_level: str,
    time_to_compromise: int
) -> str:
    score = 0
    
    # Stage scoring (1-5 points)
    stage_scores = {
        RECONNAISSANCE: 1,
        INITIAL_ACCESS: 2,
        EXPLOITATION: 3,
        PRIVILEGE_ESCALATION: 4,
        PERSISTENCE: 5,
        DATA_EXFILTRATION: 5,
        LATERAL_MOVEMENT: 4,
    }
    score += stage_scores.get(stage, 1)
    
    # Goal scoring (+2 points for serious goals)
    if goal in [DATA_THEFT, SYSTEM_COMPROMISE]:
        score += 2
    
    # Skill scoring (+1 for advanced/automated)
    if skill_level in ["advanced", "automated"]:
        score += 1
    
    # Time scoring (+1-2 points for imminent compromise)
    if 0 < time_to_compromise < 10:
        score += 2
    elif 0 < time_to_compromise < 30:
        score += 1
    
    # Classification
    if score >= 7:
        return "critical"
    elif score >= 5:
        return "high"
    elif score >= 3:
        return "medium"
    else:
        return "low"
```

### Scoring Breakdown

| Component | Points | Conditions |
|-----------|--------|------------|
| **Stage** | 1-5 | Based on attack progression |
| **Goal** | 0-2 | +2 for DATA_THEFT or SYSTEM_COMPROMISE |
| **Skill** | 0-1 | +1 for advanced/automated attacker |
| **Time** | 0-2 | +2 if compromise in <10 min, +1 if <30 min |

### Threat Level Thresholds

- **CRITICAL:** Score ≥ 7
- **HIGH:** Score ≥ 5
- **MEDIUM:** Score ≥ 3
- **LOW:** Score < 3

---

## Real-World Examples: HIGH Threat

### Example 1: Privilege Escalation Attack

**Attack Sequence:**
```
1. SQL Injection
2. SQL Injection (repeated)
3. admin_access (privilege escalation)
```

**Calculation:**
```
Stage: PRIVILEGE_ESCALATION = 4 points
Goal: SYSTEM_COMPROMISE = +2 points
Skill: intermediate = +0 points
Time: 15 minutes = +1 point

Total Score: 4 + 2 + 0 + 1 = 7 points
→ Threat Level: CRITICAL
```

### Example 2: Advanced Attacker in Exploitation Stage

**Attack Sequence:**
```
1. SQL Injection
2. UNION SELECT
3. Error-based SQL
```

**Calculation:**
```
Stage: EXPLOITATION = 3 points
Goal: DATA_THEFT = +2 points
Skill: advanced = +1 point
Time: 20 minutes = +1 point

Total Score: 3 + 2 + 1 + 1 = 7 points
→ Threat Level: CRITICAL
```

### Example 3: Fast Automated Attack

**Attack Sequence:**
```
1. SQL Injection
2. SQL Injection
3. SQL Injection
4. admin_access
```

**Calculation:**
```
Stage: PRIVILEGE_ESCALATION = 4 points
Goal: SYSTEM_COMPROMISE = +2 points
Skill: automated = +1 point
Time: 5 minutes = +2 points

Total Score: 4 + 2 + 1 + 2 = 9 points
→ Threat Level: CRITICAL
```

### Example 4: Data Exfiltration in Progress

**Attack Sequence:**
```
1. SQL Injection
2. admin_access
3. credential_extraction
4. database_dump
```

**Calculation:**
```
Stage: DATA_EXFILTRATION = 5 points
Goal: DATA_THEFT = +2 points
Skill: intermediate = +0 points
Time: -1 (already compromised) = +0 points

Total Score: 5 + 2 + 0 + 0 = 7 points
→ Threat Level: CRITICAL
```

---

## How to Trigger HIGH Threat in Demo

### Method 1: Multiple SQL Injections → Admin Access

```bash
# Attack 1: SQL Injection
http://localhost:8000/search?q=' OR 1=1--

# Attack 2: SQL Injection (repeated)
http://localhost:8000/search?q=' UNION SELECT * FROM users--

# Attack 3: Admin access attempt
http://localhost:8000/admin?user=admin' OR '1'='1

# Result: Stage = PRIVILEGE_ESCALATION (4 pts) + Goal = SYSTEM_COMPROMISE (2 pts) = 6+ pts
# → Threat Level: HIGH or CRITICAL
```

### Method 2: Rapid Attack Sequence (Automated)

```bash
# Launch 5+ attacks in quick succession (< 1 minute apart)
# This triggers:
# - Skill Level: automated (+1 point)
# - Attack Speed: high (reduces time to compromise)
# - Time to Compromise: < 10 minutes (+2 points)

# Result: Score increases by 3+ points
# → Threat Level: HIGH or CRITICAL
```

### Method 3: Data Theft Pattern

```bash
# Attack 1: SQL Injection
http://localhost:8000/search?q=' OR 1=1--

# Attack 2: Credential extraction
http://localhost:8000/search?q=' UNION SELECT username,password FROM users--

# Attack 3: Database dump
http://localhost:8000/search?q=' UNION SELECT * FROM sensitive_data--

# Result: Goal = DATA_THEFT (+2 pts) + Stage = DATA_EXFILTRATION (5 pts) = 7+ pts
# → Threat Level: CRITICAL
```

---

## Test Commands for HIGH Threat

### Quick Test (3 attacks to trigger HIGH)

```bash
# 1. Start honeypot
python app.py

# 2. Open dashboard
http://localhost:8000/demo

# 3. Launch attack sequence
http://localhost:8000/search?q=' OR 1=1--
http://localhost:8000/search?q=' UNION SELECT * FROM users--
http://localhost:8000/admin?user=admin' OR '1'='1

# 4. Check prediction API
http://localhost:8000/api/prediction/{YOUR_ATTACKER_ID}
```

**Expected Response:**
```json
{
  "attacker_id": "...",
  "current_stage": "privilege_escalation",
  "predicted_goal": "system_compromise",
  "threat_level": "high",  // or "critical"
  "time_to_compromise_minutes": 10,
  "next_likely_vectors": [
    {"vector": "admin_access", "probability": "60.0%"},
    {"vector": "command_execution", "probability": "30.0%"}
  ]
}
```

---

## Summary: When Threat Level = HIGH

### IP-Based (threat_intel.py)
✅ Abuse score > 50  
✅ Suspicious IP reputation  
✅ Tor/VPN/Proxy detected (MEDIUM, but close to HIGH)

### Attack-Based (attack_predictor.py)
✅ Score ≥ 5 points from:
  - Advanced attack stage (EXPLOITATION, PRIVILEGE_ESCALATION)
  - Serious goal (DATA_THEFT, SYSTEM_COMPROMISE)
  - Skilled attacker (advanced/automated)
  - Imminent compromise (< 30 minutes)

### Easiest Way to Demo HIGH Threat
1. Launch 3+ SQL injection attacks
2. Include "admin" in one of the payloads
3. Attack within 1-2 minutes (fast pace)

**Result:** Threat level will jump to HIGH or CRITICAL! 🚨

---

## For Judges

**Say this:**
> "The threat level automatically escalates to HIGH when we detect privilege escalation attempts or when an attacker is progressing rapidly through the attack chain. Watch the dashboard as I launch a sequence of SQL injections targeting admin access..."

Then show the threat level changing from LOW → MEDIUM → HIGH → CRITICAL in real-time!
