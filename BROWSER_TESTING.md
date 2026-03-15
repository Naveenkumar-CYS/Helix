# 🌐 Browser-Based Testing Guide

## 🚀 Quick Start

**Server must be running first!**
```powershell
python app.py
```

Then open your browser and test these URLs:

---

## 📊 1. Dashboard (Start Here!)

**Real-time attack monitoring dashboard:**
```
http://localhost:8000/dashboard
```

Keep this tab open to watch attacks appear in real-time!

---

## 🎯 2. Basic Attack Tests

### SQL Injection Attacks

**Test 1: Classic OR 1=1**
```
http://localhost:8000/search?q=' OR 1=1--
```

**Test 2: UNION SELECT**
```
http://localhost:8000/search?q=' UNION SELECT NULL--
```

**Test 3: Database Enumeration**
```
http://localhost:8000/search?q=' AND 1=2 UNION SELECT table_name FROM information_schema.tables--
```

**Test 4: Stacked Queries**
```
http://localhost:8000/search?q=test'; DROP TABLE users--
```

### XSS (Cross-Site Scripting) Attacks

**Test 5: Basic Alert**
```
http://localhost:8000/search?q=<script>alert('XSS')</script>
```

**Test 6: Image Tag XSS**
```
http://localhost:8000/search?q=<img src=x onerror=alert('XSS')>
```

**Test 7: SVG XSS**
```
http://localhost:8000/search?q=<svg onload=alert('XSS')>
```

**Test 8: Event Handler**
```
http://localhost:8000/search?q=<body onload=alert('XSS')>
```

### Command Injection Attacks

**Test 9: Linux Commands**
```
http://localhost:8000/search?q=; ls -la
```

**Test 10: Windows Commands**
```
http://localhost:8000/search?q=; dir
```

**Test 11: Pipe Commands**
```
http://localhost:8000/search?q=| cat /etc/passwd
```

**Test 12: Backtick Execution**
```
http://localhost:8000/search?q=`whoami`
```

### Path Traversal Attacks

**Test 13: Linux Path Traversal**
```
http://localhost:8000/search?q=../../etc/passwd
```

**Test 14: Windows Path Traversal**
```
http://localhost:8000/search?q=..\..\windows\system32\config\sam
```

**Test 15: Encoded Path Traversal**
```
http://localhost:8000/search?q=%2e%2e%2f%2e%2e%2fetc%2fpasswd
```

---

## 🔐 3. Admin Panel Tests

**Test 16: Admin Access (Normal)**
```
http://localhost:8000/admin
```

**Test 17: Session Hijacking**
```
http://localhost:8000/admin?session=adm_test123
```

**Test 18: Session with Special Chars**
```
http://localhost:8000/admin?session=adm_<script>alert(1)</script>
```

---

## 🎭 4. Coordinated Attack Campaign

**Run these in sequence to trigger multi-vector detection:**

1. SQL Injection:
```
http://localhost:8000/search?q=' OR 1=1--
```

2. XSS Attack:
```
http://localhost:8000/search?q=<script>alert(1)</script>
```

3. Admin Access:
```
http://localhost:8000/admin?session=adm_stolen
```

4. Path Traversal:
```
http://localhost:8000/search?q=../../etc/passwd
```

5. Command Injection:
```
http://localhost:8000/search?q=; cat /etc/passwd
```

**Watch the dashboard - you should see all 5 attacks from the same attacker ID!**

---

## 🔍 5. Advanced Testing

### Test Different Attack Sophistication Levels

**Novice (Simple)**
```
http://localhost:8000/search?q=' OR '1'='1
```

**Intermediate (Encoded)**
```
http://localhost:8000/search?q=%27%20OR%20%271%27%3D%271
```

**Advanced (Obfuscated)**
```
http://localhost:8000/search?q=' OR 1=1 UNION SELECT NULL,NULL,NULL--
```

### Test Canary Token Extraction

**Visit SQL injection multiple times and compare responses:**
```
http://localhost:8000/search?q=' OR 1=1--
```

**Notice:** Each time you visit (or from different browsers), you'll see different password hashes! These are unique canary tokens.

---

## 📱 6. Multi-Browser Testing

**Test cross-session tracking by opening these in different browsers:**

### Browser 1 (Chrome):
```
http://localhost:8000/search?q=' OR 1=1--
```

### Browser 2 (Firefox):
```
http://localhost:8000/search?q=' OR 1=1--
```

### Browser 3 (Edge):
```
http://localhost:8000/search?q=' OR 1=1--
```

**Check logs:** You'll see 3 different attacker IDs (one per browser)!

---

## 🎯 7. What to Watch For

### In the Dashboard:
- ✅ Live attack feed updates in real-time
- ✅ Total attacks counter increases
- ✅ Unique attackers counter increases
- ✅ Attack type distribution chart updates
- ✅ Skill level distribution shows your attacks

### In the Logs (attacks.log):
- ✅ Each attack has unique attacker ID
- ✅ Attack type correctly identified
- ✅ Your IP address logged
- ✅ Payload captured
- ✅ LLM response generated

### In Browser:
- ✅ Different responses for different attackers
- ✅ Unique password hashes (canary tokens)
- ✅ Realistic-looking fake data
- ✅ Delays in responses (deception timing)

---

## 🧪 8. Testing Checklist

Run through this checklist:

- [ ] Open dashboard: `http://localhost:8000/dashboard`
- [ ] Test SQL injection: `http://localhost:8000/search?q=' OR 1=1--`
- [ ] Test XSS: `http://localhost:8000/search?q=<script>alert(1)</script>`
- [ ] Test command injection: `http://localhost:8000/search?q=; ls`
- [ ] Test path traversal: `http://localhost:8000/search?q=../../etc/passwd`
- [ ] Test admin panel: `http://localhost:8000/admin?session=test`
- [ ] Run coordinated attack (all 5 attacks above)
- [ ] Check dashboard for updates
- [ ] Check `attacks.log` file
- [ ] Check `attacks.json` file
- [ ] Test in different browser (new attacker ID)
- [ ] Compare responses (different canary tokens)

---

## 📊 9. Expected Results

### After SQL Injection:
You should see HTML table with fake users:
```html
<table border="1">
<tr><th>id</th><th>username</th><th>email</th><th>password</th></tr>
<tr><td>1</td><td>admin</td><td>admin@corp.com</td><td>70c67f83996a...</td></tr>
<tr><td>2</td><td>dev</td><td>dev@corp.com</td><td>7019a5f1bdc...</td></tr>
...
</table>
```

### After XSS:
Simple response like:
```
200 OK
```

### After Admin Access:
```
Admin Dashboard
- Users
- Logs
- Backups
- System Settings
```

---

## 🎨 10. Fun Experiments

### Experiment 1: Password Hash Tracking
1. Open SQL injection URL in Browser 1
2. Note the password hash for "admin" user
3. Open same URL in Browser 2 (incognito/private)
4. Compare password hashes - they're different!
5. These are unique canary tokens per attacker

### Experiment 2: Attack Campaign
1. Keep dashboard open
2. Run all 5 coordinated attacks
3. Watch the live feed populate
4. See your attacker ID appear multiple times
5. Check if campaign is detected

### Experiment 3: Skill Level Detection
1. Run simple attack: `?q=' OR 1=1`
2. Run complex attack: `?q=' UNION SELECT NULL,NULL FROM users--`
3. Check logs for skill level classification
4. More sophisticated attacks = higher skill rating

---

## 🔧 Troubleshooting

**Dashboard not loading?**
- Make sure server is running: `python app.py`
- Check server output for errors
- Try: `http://127.0.0.1:8000/dashboard`

**Attacks not appearing in dashboard?**
- Refresh the dashboard page
- WebSocket might not be connected
- Check browser console for errors

**No logs created?**
- Check `attacks.log` and `attacks.json` in project root
- Make sure you sent at least one attack
- Check file permissions

---

## 🎯 Quick Copy-Paste Test Suite

**Copy all these URLs and paste them one by one:**

```
http://localhost:8000/dashboard
http://localhost:8000/search?q=' OR 1=1--
http://localhost:8000/search?q=<script>alert(1)</script>
http://localhost:8000/search?q=; ls -la
http://localhost:8000/search?q=../../etc/passwd
http://localhost:8000/admin?session=adm_test
http://localhost:8000/search?q=' UNION SELECT NULL--
http://localhost:8000/search?q=<img src=x onerror=alert(1)>
http://localhost:8000/search?q=| cat /etc/passwd
http://localhost:8000/admin?session=adm_<script>alert(1)</script>
```

---

## 📈 Success Criteria

After testing, you should have:
- ✅ Dashboard showing live attacks
- ✅ At least 10 attacks logged
- ✅ Multiple attack types detected (SQL, XSS, CMD, etc.)
- ✅ Unique attacker IDs per browser
- ✅ Different canary tokens per attacker
- ✅ Logs files created and populated

---

**Happy Testing! 🚀**

Watch the dashboard come alive as you test different attacks!
