"""
Canary Token Analytics Engine
Advanced analytics and tracking for canary tokens.
"""

from typing import Dict, List, Optional, Set, Tuple
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from collections import defaultdict, Counter
import json


# =========================
# DATA MODELS
# =========================
@dataclass
class CanaryTokenUsage:
    """Single usage of a canary token."""
    token_value: str
    timestamp: datetime
    location: str  # Where it was used
    attacker_id: str
    success: bool = False
    metadata: Dict = field(default_factory=dict)


@dataclass
class CanaryTokenProfile:
    """Complete profile for a canary token."""
    token_id: str
    token_value: str
    token_type: str  # credential, api_key, session, etc.
    attacker_id: str
    created_at: datetime
    extracted_from: str  # Source endpoint
    extracted_at: datetime
    
    # Usage tracking
    usage_count: int = 0
    first_used: Optional[datetime] = None
    last_used: Optional[datetime] = None
    usage_locations: List[str] = field(default_factory=list)
    usage_history: List[CanaryTokenUsage] = field(default_factory=list)
    
    # Analytics
    time_to_first_use: Optional[timedelta] = None
    is_active: bool = True
    effectiveness_score: float = 0.0
    
    def record_usage(self, location: str, success: bool = False, metadata: Optional[Dict] = None):
        """Record a usage of this token."""
        usage = CanaryTokenUsage(
            token_value=self.token_value,
            timestamp=datetime.now(),
            location=location,
            attacker_id=self.attacker_id,
            success=success,
            metadata=metadata or {}
        )
        
        self.usage_history.append(usage)
        self.usage_count += 1
        self.last_used = usage.timestamp
        
        if self.first_used is None:
            self.first_used = usage.timestamp
            self.time_to_first_use = self.first_used - self.extracted_at
        
        if location not in self.usage_locations:
            self.usage_locations.append(location)
        
        # Update effectiveness score
        self._calculate_effectiveness()
    
    def _calculate_effectiveness(self):
        """Calculate token effectiveness score (0-1)."""
        score = 0.0
        
        # Token was used (good)
        if self.usage_count > 0:
            score += 0.4
        
        # Used quickly (better)
        if self.time_to_first_use:
            hours = self.time_to_first_use.total_seconds() / 3600
            if hours < 1:
                score += 0.3
            elif hours < 24:
                score += 0.2
            else:
                score += 0.1
        
        # Used multiple times (best)
        if self.usage_count > 1:
            score += min(0.3, self.usage_count * 0.1)
        
        self.effectiveness_score = min(score, 1.0)


@dataclass
class CanaryDeployment:
    """Tracks canary deployment strategy."""
    deployment_id: str
    token_type: str
    total_deployed: int = 0
    total_extracted: int = 0
    total_used: int = 0
    extraction_rate: float = 0.0
    usage_rate: float = 0.0
    avg_time_to_extraction: Optional[timedelta] = None
    avg_time_to_use: Optional[timedelta] = None


# =========================
# CANARY ANALYTICS ENGINE
# =========================
class CanaryAnalyticsEngine:
    """Advanced analytics for canary tokens."""
    
    def __init__(self):
        self.tokens: Dict[str, CanaryTokenProfile] = {}
        self.tokens_by_attacker: Dict[str, List[str]] = defaultdict(list)
        self.deployments: Dict[str, CanaryDeployment] = {}
    
    def register_token(
        self,
        token_id: str,
        token_value: str,
        token_type: str,
        attacker_id: str,
        extracted_from: str
    ) -> CanaryTokenProfile:
        """Register a new canary token."""
        profile = CanaryTokenProfile(
            token_id=token_id,
            token_value=token_value,
            token_type=token_type,
            attacker_id=attacker_id,
            created_at=datetime.now(),
            extracted_from=extracted_from,
            extracted_at=datetime.now()
        )
        
        self.tokens[token_value] = profile
        self.tokens_by_attacker[attacker_id].append(token_value)
        
        # Update deployment stats
        if token_type not in self.deployments:
            self.deployments[token_type] = CanaryDeployment(
                deployment_id=token_type,
                token_type=token_type
            )
        
        deployment = self.deployments[token_type]
        deployment.total_deployed += 1
        deployment.total_extracted += 1
        deployment.extraction_rate = deployment.total_extracted / deployment.total_deployed
        
        return profile
    
    def record_token_usage(
        self,
        token_value: str,
        location: str,
        success: bool = False,
        metadata: Optional[Dict] = None
    ) -> bool:
        """
        Record usage of a canary token.
        
        Returns:
            True if token was found and usage recorded
        """
        if token_value not in self.tokens:
            return False
        
        profile = self.tokens[token_value]
        profile.record_usage(location, success, metadata)
        
        # Update deployment stats
        deployment = self.deployments.get(profile.token_type)
        if deployment:
            deployment.total_used = sum(
                1 for t in self.tokens.values()
                if t.token_type == profile.token_type and t.usage_count > 0
            )
            deployment.usage_rate = deployment.total_used / deployment.total_extracted if deployment.total_extracted > 0 else 0
            
            # Calculate average time to use
            times = [
                t.time_to_first_use
                for t in self.tokens.values()
                if t.token_type == profile.token_type and t.time_to_first_use
            ]
            if times:
                avg_seconds = sum(t.total_seconds() for t in times) / len(times)
                deployment.avg_time_to_use = timedelta(seconds=avg_seconds)
        
        return True
    
    def get_token_profile(self, token_value: str) -> Optional[CanaryTokenProfile]:
        """Get profile for a specific token."""
        return self.tokens.get(token_value)
    
    def get_attacker_tokens(self, attacker_id: str) -> List[CanaryTokenProfile]:
        """Get all tokens for an attacker."""
        token_values = self.tokens_by_attacker.get(attacker_id, [])
        return [self.tokens[tv] for tv in token_values if tv in self.tokens]
    
    def get_token_journey(self, token_value: str) -> Dict:
        """Get complete journey of a token."""
        profile = self.get_token_profile(token_value)
        if not profile:
            return {"error": "Token not found"}
        
        return {
            "token_id": profile.token_id,
            "token_type": profile.token_type,
            "attacker_id": profile.attacker_id,
            "extracted_from": profile.extracted_from,
            "extracted_at": profile.extracted_at.isoformat(),
            "usage_count": profile.usage_count,
            "first_used": profile.first_used.isoformat() if profile.first_used else None,
            "last_used": profile.last_used.isoformat() if profile.last_used else None,
            "time_to_first_use": str(profile.time_to_first_use) if profile.time_to_first_use else None,
            "usage_locations": profile.usage_locations,
            "effectiveness_score": f"{profile.effectiveness_score:.1%}",
            "usage_history": [
                {
                    "timestamp": u.timestamp.isoformat(),
                    "location": u.location,
                    "success": u.success
                }
                for u in profile.usage_history
            ]
        }
    
    def get_effectiveness_report(self) -> Dict:
        """Generate effectiveness report for all tokens."""
        if not self.tokens:
            return {"error": "No tokens deployed"}
        
        total_tokens = len(self.tokens)
        used_tokens = sum(1 for t in self.tokens.values() if t.usage_count > 0)
        
        # Calculate average effectiveness
        avg_effectiveness = sum(t.effectiveness_score for t in self.tokens.values()) / total_tokens
        
        # Get most effective token types
        type_effectiveness = defaultdict(list)
        for token in self.tokens.values():
            type_effectiveness[token.token_type].append(token.effectiveness_score)
        
        type_avg = {
            token_type: sum(scores) / len(scores)
            for token_type, scores in type_effectiveness.items()
        }
        
        # Sort by effectiveness
        best_types = sorted(type_avg.items(), key=lambda x: x[1], reverse=True)
        
        return {
            "total_tokens_deployed": total_tokens,
            "tokens_used": used_tokens,
            "usage_rate": f"{used_tokens / total_tokens:.1%}",
            "average_effectiveness": f"{avg_effectiveness:.1%}",
            "most_effective_types": [
                {"type": t, "effectiveness": f"{e:.1%}"}
                for t, e in best_types[:5]
            ],
            "deployments": {
                token_type: {
                    "deployed": d.total_deployed,
                    "extracted": d.total_extracted,
                    "used": d.total_used,
                    "extraction_rate": f"{d.extraction_rate:.1%}",
                    "usage_rate": f"{d.usage_rate:.1%}",
                    "avg_time_to_use": str(d.avg_time_to_use) if d.avg_time_to_use else "N/A"
                }
                for token_type, d in self.deployments.items()
            }
        }
    
    def get_attacker_canary_summary(self, attacker_id: str) -> Dict:
        """Get canary summary for an attacker."""
        tokens = self.get_attacker_tokens(attacker_id)
        
        if not tokens:
            return {"error": "No tokens for this attacker"}
        
        total_tokens = len(tokens)
        used_tokens = sum(1 for t in tokens if t.usage_count > 0)
        total_usages = sum(t.usage_count for t in tokens)
        
        # Token types extracted
        types_extracted = Counter(t.token_type for t in tokens)
        
        # Most used token
        most_used = max(tokens, key=lambda t: t.usage_count) if tokens else None
        
        return {
            "attacker_id": attacker_id,
            "total_tokens_extracted": total_tokens,
            "tokens_reused": used_tokens,
            "reuse_rate": f"{used_tokens / total_tokens:.1%}" if total_tokens > 0 else "0%",
            "total_reuse_attempts": total_usages,
            "token_types_extracted": dict(types_extracted),
            "most_reused_token": {
                "type": most_used.token_type,
                "usage_count": most_used.usage_count,
                "locations": most_used.usage_locations
            } if most_used and most_used.usage_count > 0 else None
        }
    
    def detect_token_sharing(self) -> List[Dict]:
        """Detect if tokens are being shared between attackers."""
        sharing_detected = []
        
        # Track which attackers used which tokens
        token_users: Dict[str, Set[str]] = defaultdict(set)
        
        for token_value, profile in self.tokens.items():
            # Original attacker
            token_users[token_value].add(profile.attacker_id)
            
            # Check usage history for different attackers
            for usage in profile.usage_history:
                if usage.attacker_id != profile.attacker_id:
                    token_users[token_value].add(usage.attacker_id)
        
        # Find tokens used by multiple attackers
        for token_value, attackers in token_users.items():
            if len(attackers) > 1:
                profile = self.tokens[token_value]
                sharing_detected.append({
                    "token_type": profile.token_type,
                    "token_value": token_value,
                    "original_attacker": profile.attacker_id,
                    "shared_with": list(attackers - {profile.attacker_id}),
                    "total_attackers": len(attackers)
                })
        
        return sharing_detected
    
    def generate_dashboard_data(self) -> Dict:
        """Generate data for canary analytics dashboard."""
        return {
            "overview": {
                "total_tokens": len(self.tokens),
                "active_tokens": sum(1 for t in self.tokens.values() if t.is_active),
                "used_tokens": sum(1 for t in self.tokens.values() if t.usage_count > 0),
                "total_usages": sum(t.usage_count for t in self.tokens.values())
            },
            "effectiveness": self.get_effectiveness_report(),
            "token_sharing": self.detect_token_sharing(),
            "recent_activity": [
                {
                    "token_type": t.token_type,
                    "attacker_id": t.attacker_id,
                    "last_used": t.last_used.isoformat() if t.last_used else None,
                    "usage_count": t.usage_count
                }
                for t in sorted(
                    self.tokens.values(),
                    key=lambda x: x.last_used or x.created_at,
                    reverse=True
                )[:10]
            ]
        }


# =========================
# GLOBAL INSTANCE
# =========================
_canary_analytics = CanaryAnalyticsEngine()


def register_canary_token(
    token_id: str,
    token_value: str,
    token_type: str,
    attacker_id: str,
    extracted_from: str
) -> CanaryTokenProfile:
    """Register canary token (convenience function)."""
    return _canary_analytics.register_token(
        token_id, token_value, token_type, attacker_id, extracted_from
    )


def record_canary_usage(
    token_value: str,
    location: str,
    success: bool = False,
    metadata: Optional[Dict] = None
) -> bool:
    """Record canary usage (convenience function)."""
    return _canary_analytics.record_token_usage(token_value, location, success, metadata)


def get_canary_journey(token_value: str) -> Dict:
    """Get canary journey (convenience function)."""
    return _canary_analytics.get_token_journey(token_value)


def get_canary_effectiveness() -> Dict:
    """Get effectiveness report (convenience function)."""
    return _canary_analytics.get_effectiveness_report()


def get_attacker_canaries(attacker_id: str) -> Dict:
    """Get attacker canary summary (convenience function)."""
    return _canary_analytics.get_attacker_canary_summary(attacker_id)


def get_canary_dashboard_data() -> Dict:
    """Get dashboard data (convenience function)."""
    return _canary_analytics.generate_dashboard_data()
