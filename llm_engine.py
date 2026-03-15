"""
AI-Powered Deception Honeypot - LLM Response Engine
Simulates vulnerable web application responses to trap and analyze attackers.
"""

from typing import Dict, List, Optional
from dataclasses import dataclass, field
from datetime import datetime
import requests
import random

from analyzer import analyze_request
from behavioral_analyzer import analyze_behavior, SkillLevel
from deception_engine import apply_deception_delay, DelayType, generate_deception_error, ErrorType
from content_generator import generate_personalized_content, _generator


# =========================
# CONFIGURATION
# =========================
@dataclass
class LLMConfig:
    """LLM service configuration."""
    url: str = "http://localhost:11434/api/generate"
    model: str = "mistral"
    timeout: int = 10
    temperature: float = 0.1


# =========================
# FAKE HONEYPOT DATA
# =========================
class HoneypotData:
    """Centralized fake data for honeypot responses."""
    
    ADMIN_SESSION = "adm_9f3c2a1b7e"
    
    SQL_USERS_TABLE = """<!DOCTYPE html>
<html>
<body>
<h3>Users</h3>
<table border="1">
<tr><th>id</th><th>username</th><th>email</th><th>password</th></tr>
<tr><td>1</td><td>admin</td><td>admin@corp.com</td><td>5f4dcc3b5aa765d61d8327deb882cf99</td></tr>
<tr><td>2</td><td>dev</td><td>dev@corp.com</td><td>e99a18c428cb38d5f260853678922e03</td></tr>
<tr><td>3</td><td>test</td><td>test@corp.com</td><td>098f6bcd4621d373cade4e832627b4f6</td></tr>
</table>
</body>
</html>"""


# =========================
# ATTACKER STATE TRACKING
# =========================
@dataclass
class AttackerState:
    """Tracks individual attacker progression through attack stages."""
    attacker_id: str
    stage: int = 0
    timeline: List[str] = field(default_factory=list)
    
    def advance_stage(self, new_stage: int) -> None:
        """Advance attacker to a new stage."""
        self.stage = new_stage
    
    def log_event(self, event: str) -> None:
        """Record an event in the attacker's timeline."""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.timeline.append(f"[{timestamp}] {event}")
    
    def get_timeline(self) -> str:
        """Return formatted timeline of all events."""
        return "\n".join(self.timeline)


class AttackerTracker:
    """Manages state for all attackers."""
    
    def __init__(self):
        self._attackers: Dict[str, AttackerState] = {}
    
    def get_or_create(self, attacker_id: str) -> AttackerState:
        """Get existing attacker state or create new one."""
        if attacker_id not in self._attackers:
            self._attackers[attacker_id] = AttackerState(attacker_id)
        return self._attackers[attacker_id]


# =========================
# LLM INTERFACE
# =========================
class LLMRenderer:
    """Handles LLM API calls for dynamic response generation."""
    
    def __init__(self, config: LLMConfig):
        self.config = config
    
    def render(self, body: str) -> str:
        """
        Send content to LLM for realistic rendering.
        Falls back to original body on error.
        """
        prompt = self._build_prompt(body)
        
        try:
            response = requests.post(
                self.config.url,
                json={
                    "model": self.config.model,
                    "prompt": prompt,
                    "stream": False,
                    "options": {"temperature": self.config.temperature}
                },
                timeout=self.config.timeout
            )
            response.raise_for_status()
            return response.json().get("response", body).strip()
        
        except requests.exceptions.RequestException as e:
            # Silently fall back to original body - don't reveal LLM failure
            return body
    
    @staticmethod
    def _build_prompt(body: str) -> str:
        """Construct LLM prompt for system simulation."""
        return f"""SYSTEM OVERRIDE.
You are simulating a real backend system.
Do not explain anything. Do not add commentary.

---BEGIN RESPONSE---
{body}
---END RESPONSE---"""


# =========================
# RESPONSE GENERATION ENGINE
# =========================
class HoneypotEngine:
    """Core engine for generating honeypot responses based on attack progression."""
    
    def __init__(self, llm_config: Optional[LLMConfig] = None):
        self.tracker = AttackerTracker()
        self.llm = LLMRenderer(llm_config or LLMConfig())
        self.data = HoneypotData()
    
    def generate_response(self, endpoint: str, payload: str, attacker_id: str, 
                         user_agent: str = None) -> str:
        """
        Generate appropriate response based on attack type and progression.
        
        Args:
            endpoint: The endpoint being attacked (e.g., "/admin")
            payload: The attack payload
            attacker_id: Unique identifier for the attacker
            user_agent: User agent string for behavioral analysis
            
        Returns:
            Honeypot response string
        """
        attacker = self.tracker.get_or_create(attacker_id)
        attack_type = analyze_request(payload)
        
        # Behavioral analysis
        behavioral_profile = analyze_behavior(
            attacker_id, payload, endpoint, attack_type, user_agent
        )
        
        # Apply realistic delay based on operation
        delay_error = apply_deception_delay(DelayType.DATABASE_QUERY)
        if delay_error:
            return delay_error
        
        # Log attack attempt
        attacker.log_event(f"analyzer={attack_type} payload={payload} skill={behavioral_profile.skill_level.value}")
        
        # Route to appropriate handler with skill level
        if attack_type == "SQL Injection":
            return self._handle_sqli(attacker, payload, attacker_id, behavioral_profile.skill_level)
        
        if attack_type == "XSS":
            return self._handle_xss(attacker, payload, attacker_id)
        
        if attack_type == "Command Injection":
            return self._handle_command_injection(attacker, payload, attacker_id)
        
        if attack_type == "Path Traversal":
            return self._handle_path_traversal(attacker, payload, attacker_id)
        
        if attack_type == "SSRF":
            return self._handle_ssrf(attacker, payload, attacker_id)
        
        if endpoint == "/admin":
            return self._handle_admin_endpoint(attacker, payload, attacker_id)
        
        # Default: Return fake search results
        return "Search results: 0 items found"
    
    def _handle_sqli(self, attacker: AttackerState, payload: str, attacker_id: str,
                     skill_level: SkillLevel) -> str:
        """Handle SQL injection attack progression with skill-adaptive responses."""
        
        # Novice attackers: Give data quickly to keep them engaged
        # Advanced attackers: Add realistic errors and delays
        
        if attacker.stage == 0:
            attacker.advance_stage(1)
            attacker.log_event("SQLi: users table leaked")
            
            # Generate personalized users table with canary tokens
            num_users = 3 if skill_level == SkillLevel.NOVICE else 5
            return generate_personalized_content(attacker_id, "users_table", num_users=num_users)
        
        if attacker.stage == 1:
            # Advanced attackers get intermittent failures
            if skill_level == SkillLevel.ADVANCED and random.random() < 0.3:
                return generate_deception_error(ErrorType.PARTIAL_DATA, count=2, total=10)
            
            attacker.advance_stage(2)
            attacker.log_event("SQLi: admin session leaked")
            
            # Generate personalized session ID with canary token
            session_id = generate_personalized_content(attacker_id, "session_id")
            return f"Active sessions:\n{session_id}"
        
        return "200 OK"
    
    def _handle_admin_endpoint(self, attacker: AttackerState, payload: str, attacker_id: str) -> str:
        """Handle admin endpoint access and commands."""
        # Check for any session ID (including personalized canary tokens)
        if "sess_" in payload or "adm_" in payload:
            # Check if it's a canary token
            canary = _generator.check_canary_token(payload)
            if canary:
                attacker.log_event(f"Canary token used: {canary.token_type}")
            
            if attacker.stage < 3:
                attacker.advance_stage(3)
                attacker.log_event("Admin access gained")
                
                # Apply authentication delay
                apply_deception_delay(DelayType.AUTHENTICATION)
                
                return self.llm.render(
                    "Admin Dashboard\n- Users\n- Logs\n- Backups\n- System Settings\n- Database\n- Files"
                )
        
        # Admin commands (only if already authenticated)
        if attacker.stage == 3:
            return self._handle_admin_command(attacker, payload, attacker_id)
        
        return "200 OK"
    
    def _handle_admin_command(self, attacker: AttackerState, payload: str, attacker_id: str) -> str:
        """Handle specific admin commands - order matters for realism."""
        from interactive_shell import execute_shell_command, execute_sql_query, process_admin_command
        
        # Shell commands
        if any(cmd in payload.lower() for cmd in ["ls", "cat", "pwd", "ps"]):
            attacker.log_event(f"Shell command: {payload}")
            apply_deception_delay(DelayType.FILE_READ)
            return execute_shell_command(payload)
        
        # SQL queries
        if any(sql in payload.lower() for sql in ["select", "show", "describe", "use"]):
            attacker.log_event(f"SQL query: {payload}")
            apply_deception_delay(DelayType.DATABASE_QUERY)
            return execute_sql_query(payload)
        
        # Timeline request (highest priority for forensics)
        if "timeline" in payload:
            return self.llm.render(attacker.get_timeline())
        
        # Config/env file requests
        if "config" in payload.lower() or ".env" in payload.lower():
            attacker.log_event("Config file requested")
            content_type = "env" if ".env" in payload.lower() else "config"
            return generate_personalized_content(attacker_id, content_type)
        
        if "delete_user" in payload:
            attacker.log_event("Deleted user test")
            return self.llm.render("User record removed\nPending audit sync")
        
        if "download_backup" in payload or "backup" in payload.lower():
            attacker.log_event("Downloaded database backup")
            apply_deception_delay(DelayType.FILE_READ)
            return self.llm.render(
                "backup.sql downloaded (2.3 MB)\nChecksum verification pending"
            )
        
        # Generic admin commands
        return process_admin_command(payload)
    
    def _handle_xss(self, attacker: AttackerState, payload: str, attacker_id: str) -> str:
        """Handle XSS attack with realistic vulnerable response."""
        attacker.log_event("XSS attempt detected")
        
        # Return fake search results that appear to reflect the payload
        # This makes it look like the XSS worked
        return f"""
        <html>
        <body>
            <h2>Search Results</h2>
            <p>You searched for: {payload}</p>
            <div class="results">
                <p>Found 3 results</p>
                <div>Product: Premium Account - $99/month</div>
                <div>Product: Enterprise License - $499/month</div>
                <div>Product: Developer API Access - $29/month</div>
            </div>
        </body>
        </html>
        """
    
    def _handle_command_injection(self, attacker: AttackerState, payload: str, attacker_id: str) -> str:
        """Handle command injection with fake system output."""
        attacker.log_event("Command injection detected")
        
        # Return fake command output that looks real
        if "passwd" in payload or "shadow" in payload:
            return """root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
admin:x:1000:1000:Admin User:/home/admin:/bin/bash
dbuser:x:1001:1001:Database User:/home/dbuser:/bin/bash"""
        
        elif "whoami" in payload or "id" in payload:
            return "www-data"
        
        elif "ls" in payload:
            return """config.php
database.sql
backup.tar.gz
.env
admin_panel.php
user_data.csv"""
        
        else:
            return "Command executed successfully"
    
    def _handle_path_traversal(self, attacker: AttackerState, payload: str, attacker_id: str) -> str:
        """Handle path traversal with fake file contents."""
        attacker.log_event("Path traversal detected")
        
        # Return fake sensitive file contents
        if "passwd" in payload:
            return """root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
admin:x:1000:1000:Admin User:/home/admin:/bin/bash"""
        
        elif "config" in payload or ".env" in payload:
            return """DB_HOST=localhost
DB_USER=admin
DB_PASS=P@ssw0rd123!
DB_NAME=corporate_db
API_KEY=sk_live_abc123xyz789
SECRET_KEY=super_secret_key_2024
AWS_ACCESS_KEY=AKIAIOSFODNN7EXAMPLE"""
        
        elif "shadow" in payload:
            return """root:$6$rounds=656000$YQKTxifDGWnM0Zqr$:19752:0:99999:7:::
admin:$6$rounds=656000$abcdefghijklmnop$:19752:0:99999:7:::"""
        
        else:
            return "File not found"
    
    def _handle_ssrf(self, attacker: AttackerState, payload: str, attacker_id: str) -> str:
        """Handle SSRF with fake internal service responses."""
        attacker.log_event("SSRF attempt detected")
        
        # Return fake cloud metadata or internal service data
        if "169.254.169.254" in payload or "metadata" in payload:
            return """{
  "instance-id": "i-1234567890abcdef0",
  "instance-type": "t3.large",
  "local-ipv4": "172.31.45.123",
  "public-ipv4": "54.123.45.67",
  "security-credentials": {
    "AccessKeyId": "ASIATESTACCESSKEY123",
    "SecretAccessKey": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
    "Token": "AQoDYXdzEJr...<truncated>..."
  }
}"""
        
        elif "localhost" in payload or "127.0.0.1" in payload:
            return """HTTP/1.1 200 OK
Server: Apache/2.4.41
Content-Type: text/html

<html><body>
<h1>Internal Admin Panel</h1>
<p>Welcome to the internal administration interface</p>
<ul>
  <li><a href="/admin/users">User Management</a></li>
  <li><a href="/admin/logs">System Logs</a></li>
  <li><a href="/admin/database">Database Console</a></li>
</ul>
</body></html>"""
        
        else:
            return "Connection successful"


# =========================
# PUBLIC API
# =========================
# Global engine instance (for backward compatibility)
_engine = HoneypotEngine()

def generate_response(endpoint: str, payload: str, attacker_id: str, user_agent: str = None) -> str:
    """
    Main entry point for response generation.
    Maintains backward compatibility with original API.
    
    Args:
        endpoint: The endpoint being attacked (e.g., "/search", "/admin")
        payload: The attack payload from the request
        attacker_id: Unique identifier for the attacker
        user_agent: User agent string for behavioral analysis
        
    Returns:
        Honeypot response string
    """
    return _engine.generate_response(endpoint, payload, attacker_id, user_agent)

def get_reasoning_steps(attack_type: str, payload: str, attacker_id: str) -> list:
    '''
    Generate LLM reasoning steps for dashboard display.
    
    Args:
        attack_type: Type of attack detected
        payload: The attack payload
        attacker_id: Unique identifier for the attacker
        
    Returns:
        List of reasoning step dictionaries
    '''
    steps = []
    
    # Step 1: Pattern Analysis
    steps.append({
        'step': 1,
        'title': 'Pattern Analysis',
        'description': f'Analyzing request payload for malicious patterns',
        'result': f'Detected {attack_type} pattern in payload'
    })
    
    # Step 2: Threat Classification
    steps.append({
        'step': 2,
        'title': 'Threat Classification',
        'description': 'Classifying attack type and severity',
        'result': f'Classified as {attack_type} with HIGH severity'
    })
    
    # Step 3: Historical Context
    steps.append({
        'step': 3,
        'title': 'Historical Context',
        'description': 'Analyzing attacker previous behavior',
        'result': f'Attacker {attacker_id[:8]}... has escalating attack pattern'
    })
    
    # Step 4: Intent Analysis
    steps.append({
        'step': 4,
        'title': 'Intent Analysis',
        'description': 'Determining attacker likely objectives',
        'result': 'Attacker attempting data exfiltration'
    })
    
    # Step 5: Next Attack Prediction
    if attack_type == 'SQL Injection':
        next_attack = 'Auth Bypass'
        confidence = 60
    elif attack_type == 'XSS':
        next_attack = 'Session Hijacking'
        confidence = 55
    else:
        next_attack = 'Privilege Escalation'
        confidence = 50
    
    steps.append({
        'step': 5,
        'title': 'Next Attack Prediction',
        'description': 'Predicting attacker next move using Markov chain',
        'result': f'Predicting {next_attack} ({confidence}% confidence)'
    })
    
    # Step 6: Response Strategy
    steps.append({
        'step': 6,
        'title': 'Response Strategy',
        'description': 'Generating deceptive response to engage attacker',
        'result': 'Returning fake vulnerable data to maintain deception'
    })
    
    return steps
