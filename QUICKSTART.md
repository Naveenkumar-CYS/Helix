# AI Honeypot - Quick Start Guide

## 🚀 What's New

Your honeypot is now **significantly smarter** with 10 major intelligence enhancements:

1. **Behavioral Fingerprinting** - Detects skill level (novice/intermediate/advanced/automated)
2. **Tool Signature Detection** - Identifies sqlmap, Burp Suite, Nikto, etc.
3. **Realistic Deception** - Timing delays, believable errors, fake security measures
4. **Personalized Content** - Unique canary tokens for each attacker
5. **Multi-Vector Correlation** - Tracks coordinated attacks across endpoints
6. **Threat Intelligence** - IP reputation, geolocation, attacker profiling
7. **Interactive Shell** - Fake file system, database, and admin commands
8. **Skill-Adaptive Responses** - Responses match attacker sophistication
9. **Canary Token Tracking** - Monitors data exfiltration attempts
10. **Campaign Detection** - Identifies attack stages and patterns

## 📁 New Files Created

### Intelligence Modules
- `behavioral_analyzer.py` - Skill detection & profiling
- `deception_engine.py` - Realistic delays & errors
- `content_generator.py` - Personalized data & canary tokens
- `correlation_engine.py` - Multi-vector tracking
- `threat_intel.py` - IP reputation & geolocation
- `interactive_shell.py` - Fake shell/database/admin
- `test_honeypot.py` - Comprehensive test suite

### Enhanced Core
- `llm_engine.py` - Now includes behavioral analysis & skill adaptation
- `app.py` - Integrated all intelligence systems

## 🎮 How to Use

### Start the Honeypot
```bash
python app.py
```

Server runs on `http://localhost:8000`

### Run Tests
```bash
# In another terminal
python test_honeypot.py
```

### Monitor Attacks
```bash
# View logs in real-time
tail -f attacks.log

# Or view JSON logs
tail -f attacks.json
```

## 🔍 What to Look For

### In Logs
- **Skill levels**: novice, intermediate, advanced, automated
- **Tool signatures**: sqlmap, burp_suite, manual, etc.
- **Canary tokens**: Unique per attacker (check password hashes)
- **Campaign tracking**: Multi-vector attack detection
- **Threat levels**: low, medium, high, critical

### Example Log Entry
```
attacker_id=abc123 | ip=127.0.0.1 | endpoint=/search | 
attack_type=SQL Injection | payload=' OR 1=1-- | 
llm_response=<personalized users table with canary tokens>
```

Notice: Each attacker gets **different password hashes** - those are canary tokens!

## 🧪 Test Scenarios

### 1. Basic SQL Injection
```bash
curl "http://localhost:8000/search?q=' OR 1=1--"
```
→ Returns personalized users table with canary tokens

### 2. Advanced Attack (with tool signature)
```bash
curl -H "User-Agent: sqlmap/1.0" "http://localhost:8000/search?q=' UNION SELECT NULL--"
```
→ Detected as automated, gets different response

### 3. Admin Access
```bash
curl "http://localhost:8000/admin?session=adm_9f3c2a1b7e"
```
→ Grants admin access, enables interactive commands

### 4. Interactive Commands
```bash
curl "http://localhost:8000/admin?cmd=ls /var/www/html&session=adm_9f3c2a1b7e"
curl "http://localhost:8000/admin?cmd=SELECT * FROM users&session=adm_9f3c2a1b7e"
```
→ Returns realistic file listings and database results

## 📊 Intelligence Features

### Behavioral Analysis
- Automatically classifies attacker skill level
- Adapts responses to match sophistication
- Tracks attack speed and patterns

### Deception
- Realistic delays (50-800ms based on operation)
- Believable errors (timeouts, connection issues)
- Fake security warnings (rate limits, WAF alerts)

### Personalization
- Each attacker gets unique canary tokens
- Tokens embedded in credentials, API keys, sessions
- Tracks token reuse and exfiltration

### Correlation
- Links attacks across multiple endpoints
- Detects coordinated multi-vector campaigns
- Builds attack timelines

### Threat Intel
- IP reputation analysis
- Geolocation tracking
- Comprehensive attacker profiles

## 🎯 Key Improvements

| Before | After |
|--------|-------|
| Static responses | Skill-adaptive & personalized |
| Same data for all | Unique canary tokens per attacker |
| Instant responses | Realistic delays (50-800ms) |
| No correlation | Multi-vector campaign tracking |
| Basic logging | Comprehensive intelligence data |
| Limited interaction | Full shell + database + admin |

## 📈 Next Steps

1. **Monitor logs** to see behavioral analysis in action
2. **Run test suite** to validate all features
3. **Analyze campaigns** to understand attack patterns
4. **Track canary tokens** to detect data exfiltration

## 🔧 Configuration

All intelligence systems are pre-configured with sensible defaults:
- Delays: 50-800ms based on operation type
- Error rates: 1-5% for realism
- Skill classification: Automatic based on behavior
- Canary tokens: Automatically generated per attacker

## 📚 Documentation

- **Implementation Plan**: See `implementation_plan.md` in artifacts
- **Walkthrough**: See `walkthrough.md` in artifacts
- **Task Tracking**: See `task.md` in artifacts

---

**Your honeypot is now production-ready with enterprise-level intelligence!** 🎉
