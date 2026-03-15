"""
Browser Fingerprinting Module
Tracks attackers across sessions using browser and device fingerprints.
"""

from typing import Dict, List, Optional, Set
from dataclasses import dataclass, field
from datetime import datetime
import hashlib
import json


# =========================
# BROWSER FINGERPRINT
# =========================
@dataclass
class BrowserFingerprint:
    """Browser fingerprint data."""
    fingerprint_id: str
    user_agent: str
    accept_headers: Dict[str, str] = field(default_factory=dict)
    screen_resolution: Optional[str] = None
    timezone: Optional[str] = None
    language: Optional[str] = None
    plugins: List[str] = field(default_factory=list)
    fonts: List[str] = field(default_factory=list)
    canvas_hash: Optional[str] = None
    webgl_hash: Optional[str] = None
    audio_hash: Optional[str] = None
    created_at: datetime = field(default_factory=datetime.now)


# =========================
# DEVICE FINGERPRINT
# =========================
@dataclass
class DeviceFingerprint:
    """Device-level fingerprint."""
    device_id: str
    browser_fingerprints: List[str] = field(default_factory=list)
    ip_addresses: Set[str] = field(default_factory=set)
    session_count: int = 0
    first_seen: datetime = field(default_factory=datetime.now)
    last_seen: datetime = field(default_factory=datetime.now)
    attack_count: int = 0


# =========================
# TLS FINGERPRINT
# =========================
@dataclass
class TLSFingerprint:
    """TLS/SSL fingerprint data."""
    fingerprint_hash: str
    cipher_suites: List[str] = field(default_factory=list)
    extensions: List[str] = field(default_factory=list)
    tls_version: Optional[str] = None
    ja3_hash: Optional[str] = None  # JA3 fingerprint


# =========================
# FINGERPRINT TRACKER
# =========================
class FingerprintTracker:
    """Tracks attackers across sessions using multiple fingerprinting techniques."""
    
    def __init__(self):
        self.browser_fingerprints: Dict[str, BrowserFingerprint] = {}
        self.device_fingerprints: Dict[str, DeviceFingerprint] = {}
        self.tls_fingerprints: Dict[str, TLSFingerprint] = {}
        
        # Mapping from attacker_id to fingerprints
        self.attacker_to_browser: Dict[str, Set[str]] = {}
        self.attacker_to_device: Dict[str, Set[str]] = {}
        
        # Reverse mapping from fingerprint to attackers
        self.browser_to_attackers: Dict[str, Set[str]] = {}
        self.device_to_attackers: Dict[str, Set[str]] = {}
    
    def create_browser_fingerprint(
        self,
        attacker_id: str,
        user_agent: str,
        headers: Dict[str, str],
        client_data: Optional[Dict[str, any]] = None
    ) -> str:
        """
        Create browser fingerprint from request data.
        
        Args:
            attacker_id: Attacker identifier
            user_agent: User agent string
            headers: HTTP headers
            client_data: Optional client-side fingerprint data (Canvas, WebGL, etc.)
            
        Returns:
            Fingerprint ID
        """
        # Extract accept headers
        accept_headers = {
            'accept': headers.get('accept', ''),
            'accept-encoding': headers.get('accept-encoding', ''),
            'accept-language': headers.get('accept-language', ''),
        }
        
        # Create fingerprint hash
        fp_string = f"{user_agent}|{json.dumps(accept_headers, sort_keys=True)}"
        if client_data:
            fp_string += f"|{json.dumps(client_data, sort_keys=True)}"
        
        fingerprint_id = hashlib.sha256(fp_string.encode()).hexdigest()[:16]
        
        # Create or update fingerprint
        if fingerprint_id not in self.browser_fingerprints:
            fingerprint = BrowserFingerprint(
                fingerprint_id=fingerprint_id,
                user_agent=user_agent,
                accept_headers=accept_headers
            )
            
            if client_data:
                fingerprint.screen_resolution = client_data.get('screen_resolution')
                fingerprint.timezone = client_data.get('timezone')
                fingerprint.language = client_data.get('language')
                fingerprint.plugins = client_data.get('plugins', [])
                fingerprint.fonts = client_data.get('fonts', [])
                fingerprint.canvas_hash = client_data.get('canvas_hash')
                fingerprint.webgl_hash = client_data.get('webgl_hash')
                fingerprint.audio_hash = client_data.get('audio_hash')
            
            self.browser_fingerprints[fingerprint_id] = fingerprint
        
        # Link to attacker
        if attacker_id not in self.attacker_to_browser:
            self.attacker_to_browser[attacker_id] = set()
        self.attacker_to_browser[attacker_id].add(fingerprint_id)
        
        if fingerprint_id not in self.browser_to_attackers:
            self.browser_to_attackers[fingerprint_id] = set()
        self.browser_to_attackers[fingerprint_id].add(attacker_id)
        
        return fingerprint_id
    
    def create_device_fingerprint(
        self,
        attacker_id: str,
        browser_fingerprint_id: str,
        ip_address: str
    ) -> str:
        """
        Create device-level fingerprint.
        
        Args:
            attacker_id: Attacker identifier
            browser_fingerprint_id: Browser fingerprint ID
            ip_address: IP address
            
        Returns:
            Device ID
        """
        # Device fingerprint is based on browser fingerprint
        # (in real implementation, would use more sophisticated techniques)
        device_id = browser_fingerprint_id
        
        if device_id not in self.device_fingerprints:
            self.device_fingerprints[device_id] = DeviceFingerprint(
                device_id=device_id
            )
        
        device = self.device_fingerprints[device_id]
        
        # Update device data
        if browser_fingerprint_id not in device.browser_fingerprints:
            device.browser_fingerprints.append(browser_fingerprint_id)
        
        device.ip_addresses.add(ip_address)
        device.session_count += 1
        device.last_seen = datetime.now()
        
        # Link to attacker
        if attacker_id not in self.attacker_to_device:
            self.attacker_to_device[attacker_id] = set()
        self.attacker_to_device[attacker_id].add(device_id)
        
        if device_id not in self.device_to_attackers:
            self.device_to_attackers[device_id] = set()
        self.device_to_attackers[device_id].add(attacker_id)
        
        return device_id
    
    def track_attack(self, device_id: str) -> None:
        """Track attack for device."""
        if device_id in self.device_fingerprints:
            self.device_fingerprints[device_id].attack_count += 1
    
    def find_related_attackers(self, attacker_id: str) -> Set[str]:
        """
        Find other attackers using same device/browser.
        
        Args:
            attacker_id: Attacker to check
            
        Returns:
            Set of related attacker IDs
        """
        related = set()
        
        # Find via browser fingerprint
        if attacker_id in self.attacker_to_browser:
            for browser_fp in self.attacker_to_browser[attacker_id]:
                if browser_fp in self.browser_to_attackers:
                    related.update(self.browser_to_attackers[browser_fp])
        
        # Find via device fingerprint
        if attacker_id in self.attacker_to_device:
            for device_id in self.attacker_to_device[attacker_id]:
                if device_id in self.device_to_attackers:
                    related.update(self.device_to_attackers[device_id])
        
        # Remove self
        related.discard(attacker_id)
        
        return related
    
    def is_returning_attacker(self, browser_fingerprint_id: str) -> bool:
        """Check if browser fingerprint has been seen before."""
        return browser_fingerprint_id in self.browser_fingerprints
    
    def get_fingerprint_summary(self, attacker_id: str) -> Dict[str, any]:
        """Get fingerprint summary for attacker."""
        summary = {
            "attacker_id": attacker_id,
            "browser_fingerprints": [],
            "device_fingerprints": [],
            "related_attackers": list(self.find_related_attackers(attacker_id)),
            "is_multi_session": False,
        }
        
        # Get browser fingerprints
        if attacker_id in self.attacker_to_browser:
            for fp_id in self.attacker_to_browser[attacker_id]:
                if fp_id in self.browser_fingerprints:
                    fp = self.browser_fingerprints[fp_id]
                    summary["browser_fingerprints"].append({
                        "id": fp_id,
                        "user_agent": fp.user_agent,
                        "created_at": fp.created_at.isoformat(),
                    })
        
        # Get device fingerprints
        if attacker_id in self.attacker_to_device:
            for device_id in self.attacker_to_device[attacker_id]:
                if device_id in self.device_fingerprints:
                    device = self.device_fingerprints[device_id]
                    summary["device_fingerprints"].append({
                        "id": device_id,
                        "session_count": device.session_count,
                        "attack_count": device.attack_count,
                        "ip_count": len(device.ip_addresses),
                    })
                    
                    if device.session_count > 1:
                        summary["is_multi_session"] = True
        
        return summary


# =========================
# CLIENT-SIDE FINGERPRINTING SCRIPT
# =========================
def get_fingerprinting_script() -> str:
    """
    Get JavaScript for client-side fingerprinting.
    This would be injected into honeypot responses.
    """
    return """
<script>
(function() {
    const fingerprint = {
        screen_resolution: screen.width + 'x' + screen.height,
        timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
        language: navigator.language,
        plugins: Array.from(navigator.plugins).map(p => p.name),
        canvas_hash: null,
        webgl_hash: null
    };
    
    // Canvas fingerprinting
    try {
        const canvas = document.createElement('canvas');
        const ctx = canvas.getContext('2d');
        ctx.textBaseline = 'top';
        ctx.font = '14px Arial';
        ctx.fillText('Fingerprint', 2, 2);
        fingerprint.canvas_hash = canvas.toDataURL().slice(-50);
    } catch(e) {}
    
    // WebGL fingerprinting
    try {
        const canvas = document.createElement('canvas');
        const gl = canvas.getContext('webgl');
        const debugInfo = gl.getExtension('WEBGL_debug_renderer_info');
        if (debugInfo) {
            const vendor = gl.getParameter(debugInfo.UNMASKED_VENDOR_WEBGL);
            const renderer = gl.getParameter(debugInfo.UNMASKED_RENDERER_WEBGL);
            fingerprint.webgl_hash = vendor + '|' + renderer;
        }
    } catch(e) {}
    
    // Send fingerprint to server
    fetch('/api/fingerprint', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify(fingerprint)
    });
})();
</script>
"""


# =========================
# GLOBAL INSTANCE
# =========================
_fingerprint_tracker = FingerprintTracker()


def track_browser_fingerprint(
    attacker_id: str,
    user_agent: str,
    headers: Dict[str, str],
    ip_address: str,
    client_data: Optional[Dict[str, any]] = None
) -> Dict[str, any]:
    """Track browser and device fingerprints (convenience function)."""
    browser_fp = _fingerprint_tracker.create_browser_fingerprint(
        attacker_id, user_agent, headers, client_data
    )
    
    device_id = _fingerprint_tracker.create_device_fingerprint(
        attacker_id, browser_fp, ip_address
    )
    
    _fingerprint_tracker.track_attack(device_id)
    
    return _fingerprint_tracker.get_fingerprint_summary(attacker_id)


def find_related_attackers(attacker_id: str) -> List[str]:
    """Find related attackers (convenience function)."""
    return list(_fingerprint_tracker.find_related_attackers(attacker_id))


def is_returning_attacker(browser_fingerprint_id: str) -> bool:
    """Check if returning attacker (convenience function)."""
    return _fingerprint_tracker.is_returning_attacker(browser_fingerprint_id)
