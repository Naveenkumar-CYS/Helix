"""
Active Counter-Intelligence Module
Implements tool poisoning, reverse fingerprinting, and anti-detection techniques.
"""

from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, field
from datetime import datetime
import random
import hashlib


# =========================
# TOOL POISONING
# =========================
class ToolPoisoner:
    """Poisons automated attack tools with malformed data."""
    
    def __init__(self):
        self.poison_rate = 0.3  # 30% chance to poison
    
    def poison_sqlmap(self, payload: str) -> Optional[str]:
        """
        Poison sqlmap with responses that cause errors or infinite loops.
        
        Returns:
            Poisoned response or None if not poisoning
        """
        if random.random() > self.poison_rate:
            return None
        
        # Different poison techniques
        techniques = [
            self._infinite_redirect_poison,
            self._malformed_html_poison,
            self._resource_exhaustion_poison,
            self._encoding_confusion_poison,
        ]
        
        technique = random.choice(techniques)
        return technique()
    
    def _infinite_redirect_poison(self) -> str:
        """Create circular redirect that wastes tool time."""
        return """HTTP/1.1 302 Found
Location: /search?q=redirect&next=/search?q=redirect2&next=/search?q=redirect3
Content-Length: 0

"""
    
    def _malformed_html_poison(self) -> str:
        """Return deeply nested HTML that causes parser issues."""
        nested = "<div>" * 1000 + "data" + "</div>" * 1000
        return f"""HTTP/1.1 200 OK
Content-Type: text/html

<!DOCTYPE html>
<html>
<body>
{nested}
</body>
</html>
"""
    
    def _resource_exhaustion_poison(self) -> str:
        """Return huge response to exhaust memory."""
        # Generate large fake data
        fake_data = "x" * 10000
        return f"""HTTP/1.1 200 OK
Content-Type: text/html
Content-Length: 1000000

<!DOCTYPE html>
<html>
<body>
<table>
{'<tr><td>' + fake_data + '</td></tr>' * 100}
</table>
</body>
</html>
"""
    
    def _encoding_confusion_poison(self) -> str:
        """Mix encodings to confuse parsers."""
        return """HTTP/1.1 200 OK
Content-Type: text/html; charset=UTF-8

<!DOCTYPE html>
<html>
<head><meta charset="ISO-8859-1"></head>
<body>
<p>Users: &#x0041;&#x0042;&#x0043;</p>
<p>Data: %41%42%43</p>
<p>More: \x41\x42\x43</p>
</body>
</html>
"""
    
    def poison_burp(self, payload: str) -> Optional[str]:
        """Poison Burp Suite with misleading responses."""
        if random.random() > self.poison_rate:
            return None
        
        # Return fake vulnerabilities to waste time
        return """HTTP/1.1 200 OK
Content-Type: text/html

<!DOCTYPE html>
<html>
<body>
<!-- DEBUG MODE ENABLED -->
<!-- Database: mysql://admin:password@localhost/production -->
<!-- API Key: fake_key_12345 -->
<!-- Session: fake_session_token -->
<h1>Debug Information</h1>
<pre>
Error: Connection timeout
Stack trace:
  at Database.connect()
  at UserController.login()
</pre>
</body>
</html>
"""


# =========================
# REVERSE FINGERPRINTING
# =========================
@dataclass
class AttackerInfrastructure:
    """Information about attacker's infrastructure."""
    attacker_id: str
    ip_addresses: List[str] = field(default_factory=list)
    user_agents: List[str] = field(default_factory=list)
    tools_detected: List[str] = field(default_factory=list)
    request_patterns: Dict[str, int] = field(default_factory=dict)
    timing_patterns: List[float] = field(default_factory=list)
    header_fingerprint: Optional[str] = None
    tls_fingerprint: Optional[str] = None


class ReverseFingerprinter:
    """Collects information about attacker's infrastructure and tools."""
    
    def __init__(self):
        self.infrastructure: Dict[str, AttackerInfrastructure] = {}
    
    def fingerprint_attacker(
        self,
        attacker_id: str,
        ip: str,
        user_agent: str,
        headers: Dict[str, str],
        timing: float
    ) -> AttackerInfrastructure:
        """
        Collect fingerprinting data about attacker.
        
        Args:
            attacker_id: Attacker identifier
            ip: IP address
            user_agent: User agent string
            headers: HTTP headers
            timing: Request timing
            
        Returns:
            Updated infrastructure profile
        """
        if attacker_id not in self.infrastructure:
            self.infrastructure[attacker_id] = AttackerInfrastructure(attacker_id)
        
        infra = self.infrastructure[attacker_id]
        
        # Track IPs
        if ip not in infra.ip_addresses:
            infra.ip_addresses.append(ip)
        
        # Track user agents
        if user_agent and user_agent not in infra.user_agents:
            infra.user_agents.append(user_agent)
        
        # Detect tools from user agent
        tools = self._detect_tools(user_agent)
        for tool in tools:
            if tool not in infra.tools_detected:
                infra.tools_detected.append(tool)
        
        # Track request patterns
        pattern = self._extract_pattern(headers)
        infra.request_patterns[pattern] = infra.request_patterns.get(pattern, 0) + 1
        
        # Track timing
        infra.timing_patterns.append(timing)
        if len(infra.timing_patterns) > 100:
            infra.timing_patterns.pop(0)
        
        # Generate header fingerprint
        infra.header_fingerprint = self._fingerprint_headers(headers)
        
        return infra
    
    def _detect_tools(self, user_agent: str) -> List[str]:
        """Detect attack tools from user agent."""
        if not user_agent:
            return []
        
        ua_lower = user_agent.lower()
        tools = []
        
        tool_signatures = {
            'sqlmap': 'sqlmap',
            'burp': 'burp',
            'nikto': 'nikto',
            'nmap': 'nmap',
            'metasploit': 'metasploit',
            'python-requests': 'python',
            'curl': 'curl',
            'wget': 'wget',
        }
        
        for tool, signature in tool_signatures.items():
            if signature in ua_lower:
                tools.append(tool)
        
        return tools
    
    def _extract_pattern(self, headers: Dict[str, str]) -> str:
        """Extract request pattern from headers."""
        # Create pattern from header order and presence
        header_keys = sorted(headers.keys())
        return hashlib.md5(','.join(header_keys).encode()).hexdigest()[:8]
    
    def _fingerprint_headers(self, headers: Dict[str, str]) -> str:
        """Generate fingerprint from HTTP headers."""
        # Create fingerprint from specific headers
        fp_headers = ['accept', 'accept-encoding', 'accept-language', 'connection']
        fp_values = [headers.get(h, '') for h in fp_headers]
        fp_string = '|'.join(fp_values)
        return hashlib.sha256(fp_string.encode()).hexdigest()[:16]
    
    def get_infrastructure_summary(self, attacker_id: str) -> Dict[str, any]:
        """Get summary of attacker's infrastructure."""
        if attacker_id not in self.infrastructure:
            return {}
        
        infra = self.infrastructure[attacker_id]
        
        # Calculate average timing
        avg_timing = sum(infra.timing_patterns) / len(infra.timing_patterns) if infra.timing_patterns else 0
        
        return {
            "attacker_id": attacker_id,
            "ip_count": len(infra.ip_addresses),
            "ips": infra.ip_addresses,
            "user_agents": infra.user_agents,
            "tools": infra.tools_detected,
            "avg_request_time": avg_timing,
            "is_automated": avg_timing < 0.5,  # Fast requests = automated
            "header_fingerprint": infra.header_fingerprint,
        }


# =========================
# FAKE VULNERABILITY ADVERTISING
# =========================
class FakeVulnerabilityAdvertiser:
    """Advertises fake vulnerabilities to attract and waste attacker time."""
    
    def __init__(self):
        self.fake_vulns = [
            {
                "type": "SQL Injection",
                "endpoint": "/api/v2/users",
                "hint": "<!-- TODO: Fix SQL injection in user search -->",
                "payload": "?search=' OR 1=1--"
            },
            {
                "type": "File Upload",
                "endpoint": "/upload",
                "hint": "<!-- No file type validation -->",
                "payload": "Upload .php file"
            },
            {
                "type": "XXE",
                "endpoint": "/api/xml",
                "hint": "<!-- XML parser not configured securely -->",
                "payload": "Send XML with external entity"
            },
            {
                "type": "SSRF",
                "endpoint": "/fetch",
                "hint": "<!-- Internal URL fetcher -->",
                "payload": "?url=http://localhost:8080"
            },
        ]
    
    def inject_fake_vulnerability(self, response: str, skill_level: str) -> str:
        """
        Inject hints about fake vulnerabilities into response.
        
        Args:
            response: Original response
            skill_level: Attacker skill level
            
        Returns:
            Response with injected hints
        """
        # Only inject for intermediate/advanced attackers
        if skill_level not in ['INTERMEDIATE', 'ADVANCED']:
            return response
        
        # 40% chance to inject
        if random.random() > 0.4:
            return response
        
        vuln = random.choice(self.fake_vulns)
        
        # Inject as HTML comment
        hint = f"\n<!-- {vuln['hint']} -->\n"
        
        # Try to inject before </body>
        if '</body>' in response:
            return response.replace('</body>', hint + '</body>')
        
        # Otherwise append
        return response + hint
    
    def get_fake_endpoints(self) -> List[str]:
        """Get list of fake vulnerable endpoints."""
        return [v['endpoint'] for v in self.fake_vulns]


# =========================
# HONEYPOT DETECTION EVASION
# =========================
class HoneypotDetectionEvasion:
    """Techniques to avoid being detected as a honeypot."""
    
    def __init__(self):
        self.evasion_techniques = {
            'realistic_errors': True,
            'variable_timing': True,
            'consistent_state': True,
            'believable_data': True,
        }
    
    def add_realistic_inconsistencies(self, response: str) -> str:
        """Add realistic inconsistencies that real systems have."""
        # Real systems have minor bugs and inconsistencies
        # Add random whitespace variations
        if random.random() < 0.3:
            response = response.replace('  ', ' ')
        
        # Occasionally add trailing whitespace
        if random.random() < 0.2:
            response += ' \n'
        
        return response
    
    def vary_response_timing(self, base_delay: float) -> float:
        """Vary response timing to avoid detection."""
        # Add realistic jitter (±20%)
        jitter = random.uniform(-0.2, 0.2)
        return base_delay * (1 + jitter)
    
    def should_show_error(self, error_rate: float = 0.05) -> bool:
        """Decide if should show error (real systems have errors)."""
        return random.random() < error_rate


# =========================
# GLOBAL INSTANCES
# =========================
_tool_poisoner = ToolPoisoner()
_reverse_fingerprinter = ReverseFingerprinter()
_fake_vuln_advertiser = FakeVulnerabilityAdvertiser()
_evasion = HoneypotDetectionEvasion()


def poison_tool_response(tool: str, payload: str) -> Optional[str]:
    """Poison automated tool response (convenience function)."""
    if tool == 'sqlmap':
        return _tool_poisoner.poison_sqlmap(payload)
    elif tool == 'burp':
        return _tool_poisoner.poison_burp(payload)
    return None


def fingerprint_attacker(
    attacker_id: str,
    ip: str,
    user_agent: str,
    headers: Dict[str, str],
    timing: float
) -> Dict[str, any]:
    """Fingerprint attacker infrastructure (convenience function)."""
    infra = _reverse_fingerprinter.fingerprint_attacker(
        attacker_id, ip, user_agent, headers, timing
    )
    return _reverse_fingerprinter.get_infrastructure_summary(attacker_id)


def inject_fake_vulnerability(response: str, skill_level: str) -> str:
    """Inject fake vulnerability hints (convenience function)."""
    return _fake_vuln_advertiser.inject_fake_vulnerability(response, skill_level)


def add_evasion_techniques(response: str, base_delay: float) -> Tuple[str, float]:
    """Add honeypot detection evasion (convenience function)."""
    response = _evasion.add_realistic_inconsistencies(response)
    delay = _evasion.vary_response_timing(base_delay)
    return response, delay
