"""
Adaptive Deception Engine
Adjusts deception strategies based on attacker skill level and behavior.
"""

from typing import Dict, List, Optional
from dataclasses import dataclass
from enum import Enum
import random


# =========================
# ENUMS
# =========================
class DeceptionStrategy(Enum):
    """Deception strategies by skill level."""
    EASY_WIN = "easy_win"  # Let novice succeed quickly
    MODERATE_CHALLENGE = "moderate_challenge"  # Balance for intermediate
    RABBIT_HOLE = "rabbit_hole"  # Waste advanced attacker time
    HONEYPOT_EVASION = "honeypot_evasion"  # Avoid detection


# =========================
# ADAPTIVE DECEPTION ENGINE
# =========================
class AdaptiveDeceptionEngine:
    """Adapts deception based on attacker skill."""
    
    def __init__(self):
        self.attacker_strategies: Dict[str, DeceptionStrategy] = {}
    
    def select_strategy(self, attacker_id: str, skill_level: str) -> DeceptionStrategy:
        """Select deception strategy based on skill level."""
        if attacker_id in self.attacker_strategies:
            return self.attacker_strategies[attacker_id]
        
        # Map skill to strategy
        strategy_map = {
            "novice": DeceptionStrategy.EASY_WIN,
            "intermediate": DeceptionStrategy.MODERATE_CHALLENGE,
            "advanced": DeceptionStrategy.RABBIT_HOLE,
            "automated": DeceptionStrategy.HONEYPOT_EVASION
        }
        
        strategy = strategy_map.get(skill_level, DeceptionStrategy.MODERATE_CHALLENGE)
        self.attacker_strategies[attacker_id] = strategy
        return strategy
    
    def adjust_response_complexity(
        self,
        base_response: str,
        strategy: DeceptionStrategy
    ) -> str:
        """Adjust response complexity based on strategy."""
        if strategy == DeceptionStrategy.EASY_WIN:
            # Make it obvious and easy
            return base_response
        
        elif strategy == DeceptionStrategy.RABBIT_HOLE:
            # Add misleading complexity
            rabbit_holes = [
                "\n<!-- Debug: Check /backup/old_db.sql for more data -->",
                "\n<!-- TODO: Move sensitive data from /tmp/secrets.txt -->",
                "\n<!-- Note: Admin panel at /secret_admin_v2 -->",
            ]
            return base_response + random.choice(rabbit_holes)
        
        elif strategy == DeceptionStrategy.HONEYPOT_EVASION:
            # Make responses more realistic
            return base_response.replace("honeypot", "application")
        
        return base_response
    
    def generate_fake_vulnerability_hint(
        self,
        strategy: DeceptionStrategy
    ) -> Optional[str]:
        """Generate fake vulnerability hints."""
        if strategy == DeceptionStrategy.EASY_WIN:
            hints = [
                "<!-- SQL injection possible on search parameter -->",
                "<!-- XSS vulnerability in comment field -->",
            ]
            return random.choice(hints)
        
        elif strategy == DeceptionStrategy.RABBIT_HOLE:
            hints = [
                "<!-- Check /api/v2/internal for undocumented endpoints -->",
                "<!-- Legacy auth bypass: add ?debug=true -->",
                "<!-- File upload at /upload accepts .php files -->",
            ]
            return random.choice(hints)
        
        return None
    
    def calculate_delay(
        self,
        base_delay: float,
        strategy: DeceptionStrategy
    ) -> float:
        """Calculate response delay based on strategy."""
        if strategy == DeceptionStrategy.EASY_WIN:
            return base_delay * 0.5  # Fast responses
        
        elif strategy == DeceptionStrategy.RABBIT_HOLE:
            return base_delay * 2.0  # Slow them down
        
        return base_delay


# =========================
# GLOBAL INSTANCE
# =========================
_adaptive_deception = AdaptiveDeceptionEngine()


def get_deception_strategy(attacker_id: str, skill_level: str) -> DeceptionStrategy:
    """Get deception strategy (convenience function)."""
    return _adaptive_deception.select_strategy(attacker_id, skill_level)


def adapt_response(response: str, attacker_id: str, skill_level: str) -> str:
    """Adapt response (convenience function)."""
    strategy = _adaptive_deception.select_strategy(attacker_id, skill_level)
    return _adaptive_deception.adjust_response_complexity(response, strategy)
