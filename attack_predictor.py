"""
AI-Powered Attack Prediction Engine
Predicts next attack vectors and attacker goals using Markov chains and pattern analysis.
"""

from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from collections import defaultdict, Counter
from enum import Enum
import json


# =========================
# ENUMS
# =========================
class AttackStage(Enum):
    """Attack campaign stages."""
    RECONNAISSANCE = "reconnaissance"
    INITIAL_ACCESS = "initial_access"
    EXPLOITATION = "exploitation"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    PERSISTENCE = "persistence"
    DATA_EXFILTRATION = "data_exfiltration"
    LATERAL_MOVEMENT = "lateral_movement"


class AttackGoal(Enum):
    """Predicted attacker goals."""
    DATA_THEFT = "data_theft"
    SYSTEM_COMPROMISE = "system_compromise"
    CREDENTIAL_HARVESTING = "credential_harvesting"
    RECONNAISSANCE_ONLY = "reconnaissance_only"
    AUTOMATED_SCANNING = "automated_scanning"
    PRIVILEGE_ESCALATION = "privilege_escalation"


# =========================
# DATA MODELS
# =========================
@dataclass
class AttackSequence:
    """Sequence of attack actions."""
    attacker_id: str
    actions: List[str] = field(default_factory=list)
    timestamps: List[datetime] = field(default_factory=list)
    endpoints: List[str] = field(default_factory=list)
    current_stage: AttackStage = AttackStage.RECONNAISSANCE
    
    def add_action(self, action: str, endpoint: str):
        """Add action to sequence."""
        self.actions.append(action)
        self.endpoints.append(endpoint)
        self.timestamps.append(datetime.now())


@dataclass
class AttackPrediction:
    """Prediction of next attack actions."""
    attacker_id: str
    next_likely_vectors: List[Tuple[str, float]] = field(default_factory=list)  # (vector, probability)
    predicted_goal: AttackGoal = AttackGoal.RECONNAISSANCE_ONLY
    goal_confidence: float = 0.0
    current_stage: AttackStage = AttackStage.RECONNAISSANCE
    next_stage: Optional[AttackStage] = None
    time_to_compromise: Optional[int] = None  # minutes
    recommended_defenses: List[str] = field(default_factory=list)
    threat_level: str = "low"


# =========================
# MARKOV CHAIN PREDICTOR
# =========================
class MarkovChainPredictor:
    """
    A production-grade Markov chain predictor for attack sequence analysis.
    
    This class implements a first-order Markov chain model that learns attack transition
    patterns and predicts the most likely next attack vectors. It uses Laplace smoothing
    to handle unseen transitions and provides structured predictions with confidence scores.
    
    Key features:
    - Learns from attack sequences with incremental updates
    - Handles unknown attack types gracefully
    - Provides smoothed probability estimates
    - Returns structured predictions for easy consumption
    
    Attributes:
        transitions: Dict of state -> next_state -> probability
        transition_counts: Raw transition counts for learning
        all_states: Set of all known attack states
        total_sequences: Total number of learned sequences
    """
    
    def __init__(self):
        """
        Initialize the Markov chain predictor with common attack patterns.
        
        Sets up the transition matrices and initializes with known attack sequences
        from cybersecurity research and common attack chains.
        """
        # Transition probabilities: current_state -> next_state -> probability
        self.transitions: Dict[str, Dict[str, float]] = defaultdict(lambda: defaultdict(float))
        self.transition_counts: Dict[str, Dict[str, int]] = defaultdict(lambda: defaultdict(int))
        self.total_sequences = 0
        self.all_states = set()  # Track all known states for smoothing
        
        # Initialize with common attack patterns
        self._initialize_common_patterns()
    
    def _initialize_common_patterns(self):
        """
        Initialize the model with known attack progression patterns.
        
        Populates the transition matrices with realistic attack chains based on
        common cybersecurity attack patterns, including reconnaissance, exploitation,
        privilege escalation, and data exfiltration phases.
        """
        # Common attack progressions based on real-world patterns
        common_patterns = [
            # SQL Injection attack chain
            ["reconnaissance", "SQL Injection", "credential_extraction"],
            ["SQL Injection", "credential_extraction", "admin_access"],
            ["credential_extraction", "admin_access", "command_execution"],
            ["admin_access", "command_execution", "data_exfiltration"],
            
            # XSS attack chain
            ["reconnaissance", "XSS", "session_hijacking"],
            ["XSS", "session_hijacking", "credential_extraction"],
            ["session_hijacking", "admin_access", "command_execution"],
            
            # Brute force chain
            ["reconnaissance", "brute_force", "credential_stuffing"],
            ["brute_force", "credential_stuffing", "admin_access"],
            
            # Path traversal chain
            ["reconnaissance", "PATH_TRAVERSAL", "credential_extraction"],
            ["PATH_TRAVERSAL", "admin_access", "data_exfiltration"],
            
            # Command injection chain
            ["reconnaissance", "CMD_INJECTION", "command_execution"],
            ["CMD_INJECTION", "data_exfiltration"],
            
            # Authentication bypass
            ["reconnaissance", "Authentication Bypass", "admin_access"],
            
            # SSRF chain
            ["reconnaissance", "SSRF", "credential_extraction"],
            ["SSRF", "admin_access"],
            
            # Deserialization
            ["reconnaissance", "Insecure Deserialization", "command_execution"],
            
            # Additional realistic sequences
            ["SQL Injection", "admin_access", "command_execution"],
            ["XSS", "SQL Injection", "admin_access"],
            ["brute_force", "SQL Injection", "admin_access"],
            ["PATH_TRAVERSAL", "CMD_INJECTION", "data_exfiltration"],
        ]
        
        for pattern in common_patterns:
            for state in pattern:
                self.all_states.add(state)
            for i in range(len(pattern) - 1):
                self.learn_transition(pattern[i], pattern[i + 1])
        
        # After learning all initial transitions, update probabilities for all states
        for state in self.all_states:
            self._update_probabilities(state)
    
    def learn_transition(self, current_state: str, next_state: str):
        """
        Learn a single state transition from attack logs.
        
        Updates the transition counts and recalculates probabilities with smoothing.
        This method is called incrementally as new attack data is observed.
        
        Args:
            current_state: The current attack type (e.g., "SQL Injection")
            next_state: The next attack type in sequence
        """
        self.transition_counts[current_state][next_state] += 1
        self.all_states.add(current_state)
        self.all_states.add(next_state)
        
        # Recalculate probabilities for this state with Laplace smoothing
        self._update_probabilities(current_state)
    
    def _update_probabilities(self, state: str):
        """
        Update smoothed transition probabilities for a given state.
        
        Uses Laplace smoothing (add-one smoothing) to ensure all possible transitions
        have non-zero probability, preventing prediction failures for unseen combinations.
        
        Args:
            state: The state for which to update probabilities
        """
        counts = self.transition_counts[state]  # This creates it if not exists
        
        if not counts:  # No learned transitions, use uniform distribution
            num_states = len(self.all_states)
            uniform_prob = 1.0 / num_states if num_states > 0 else 0.0
            for next_state in self.all_states:
                self.transitions[state][next_state] = uniform_prob
        else:  # Has learned transitions, apply Laplace smoothing
            total = sum(counts.values())
            num_states = len(self.all_states)
            
            # Laplace smoothing: add 1 to each possible transition
            for next_state in self.all_states:
                smoothed_count = counts.get(next_state, 0) + 1
                smoothed_total = total + num_states
                self.transitions[state][next_state] = smoothed_count / smoothed_total
    
    def predict_next(self, current_state: str, top_k: int = 3) -> Dict[str, Any]:
        """
        Predict the next most likely attack states using Markov chain analysis.
        
        This method uses a first-order Markov chain with Laplace smoothing to predict
        the most probable next attack vectors based on learned transition probabilities.
        For unknown states, it provides uniform probability distribution across all known states.
        
        Args:
            current_state: The current attack state (e.g., "SQL Injection", "XSS")
            top_k: Number of top predictions to return (default: 3)
            
        Returns:
            Dict containing:
            - 'predicted_attack': The most likely next attack (str)
            - 'confidence': Confidence score for the top prediction (0.0-1.0)
            - 'top_predictions': List of (attack, probability) tuples, sorted by probability desc
        """
        # Handle unknown states by adding them and computing uniform probabilities
        if current_state not in self.all_states:
            self.all_states.add(current_state)
            # Update probabilities for all states since all_states changed
            for state in self.all_states:
                self._update_probabilities(state)
        elif current_state not in self.transitions:
            self._update_probabilities(current_state)
        
        # Get all possible next states with probabilities
        next_states = self.transitions.get(current_state, {})
        
        if not next_states:
            # Fallback for completely empty transitions (shouldn't happen with smoothing)
            return {
                'predicted_attack': 'reconnaissance',
                'confidence': 0.0,
                'top_predictions': [('reconnaissance', 1.0)]
            }
        
        # Sort by probability descending
        sorted_states = sorted(
            next_states.items(),
            key=lambda x: x[1],
            reverse=True
        )
        
        top_predictions = sorted_states[:top_k]
        
        return {
            'predicted_attack': top_predictions[0][0] if top_predictions else 'reconnaissance',
            'confidence': top_predictions[0][1] if top_predictions else 0.0,
            'top_predictions': top_predictions
        }
    
    def learn_sequence(self, sequence: List[str]):
        """
        Learn transition patterns from a complete attack sequence.
        
        Processes an entire sequence of attack types and updates the transition
        probabilities for each consecutive pair. This is useful for batch learning
        from historical attack data.
        
        Args:
            sequence: List of attack types in chronological order
        """
        for i in range(len(sequence) - 1):
            self.learn_transition(sequence[i], sequence[i + 1])
        self.total_sequences += 1


# =========================
# ATTACK STAGE CLASSIFIER
# =========================
class AttackStageClassifier:
    """Classifies current attack stage based on actions."""
    
    def __init__(self):
        self.stage_indicators = {
            AttackStage.RECONNAISSANCE: [
                "normal", "scan", "probe", "enumerate"
            ],
            AttackStage.INITIAL_ACCESS: [
                "SQL Injection", "XSS", "command_injection", "path_traversal"
            ],
            AttackStage.EXPLOITATION: [
                "SQL Injection", "union_select", "error_based"
            ],
            AttackStage.PRIVILEGE_ESCALATION: [
                "admin_access", "privilege", "sudo", "root"
            ],
            AttackStage.PERSISTENCE: [
                "backdoor", "cron", "service", "startup"
            ],
            AttackStage.DATA_EXFILTRATION: [
                "credential", "database", "dump", "export", "download"
            ],
            AttackStage.LATERAL_MOVEMENT: [
                "ssh", "rdp", "smb", "network"
            ]
        }
    
    def classify_stage(self, actions: List[str]) -> AttackStage:
        """Classify current attack stage based on recent actions."""
        if not actions:
            return AttackStage.RECONNAISSANCE
        
        # Look at last 5 actions
        recent_actions = actions[-5:]
        
        # Count indicators for each stage
        stage_scores = defaultdict(int)
        for action in recent_actions:
            action_lower = action.lower()
            for stage, indicators in self.stage_indicators.items():
                for indicator in indicators:
                    if indicator in action_lower:
                        stage_scores[stage] += 1
        
        # Return stage with highest score
        if stage_scores:
            return max(stage_scores.items(), key=lambda x: x[1])[0]
        
        return AttackStage.RECONNAISSANCE
    
    def predict_next_stage(self, current_stage: AttackStage) -> Optional[AttackStage]:
        """Predict next likely stage in attack progression."""
        progression = {
            AttackStage.RECONNAISSANCE: AttackStage.INITIAL_ACCESS,
            AttackStage.INITIAL_ACCESS: AttackStage.EXPLOITATION,
            AttackStage.EXPLOITATION: AttackStage.PRIVILEGE_ESCALATION,
            AttackStage.PRIVILEGE_ESCALATION: AttackStage.DATA_EXFILTRATION,
            AttackStage.DATA_EXFILTRATION: None,  # Terminal stage
            AttackStage.PERSISTENCE: AttackStage.LATERAL_MOVEMENT,
            AttackStage.LATERAL_MOVEMENT: AttackStage.DATA_EXFILTRATION,
        }
        
        return progression.get(current_stage)


# =========================
# GOAL PREDICTOR
# =========================
class AttackGoalPredictor:
    """Predicts attacker's end goal based on behavior."""
    
    def predict_goal(
        self,
        actions: List[str],
        endpoints: List[str],
        skill_level: str
    ) -> Tuple[AttackGoal, float]:
        """
        Predict attacker's goal.
        
        Returns:
            (predicted_goal, confidence)
        """
        action_str = " ".join(actions).lower()
        endpoint_str = " ".join(endpoints).lower()
        
        # Goal indicators
        goal_scores = defaultdict(float)
        
        # Data theft indicators
        if any(word in action_str for word in ["credential", "password", "dump", "export"]):
            goal_scores[AttackGoal.DATA_THEFT] += 0.4
        if "admin" in endpoint_str:
            goal_scores[AttackGoal.DATA_THEFT] += 0.2
        
        # System compromise indicators
        if any(word in action_str for word in ["command", "shell", "exec", "admin"]):
            goal_scores[AttackGoal.SYSTEM_COMPROMISE] += 0.4
        
        # Credential harvesting
        if action_str.count("brute") > 2 or "credential_stuffing" in action_str:
            goal_scores[AttackGoal.CREDENTIAL_HARVESTING] += 0.5
        
        # Reconnaissance only
        if len(actions) < 5 and "normal" in action_str:
            goal_scores[AttackGoal.RECONNAISSANCE_ONLY] += 0.3
        
        # Automated scanning
        if skill_level == "automated" or len(actions) > 20:
            goal_scores[AttackGoal.AUTOMATED_SCANNING] += 0.4
        
        # Privilege escalation
        if "admin" in action_str and "sql" in action_str:
            goal_scores[AttackGoal.PRIVILEGE_ESCALATION] += 0.3
        
        # Get highest scoring goal
        if goal_scores:
            goal, score = max(goal_scores.items(), key=lambda x: x[1])
            confidence = min(score, 1.0)
            return goal, confidence
        
        return AttackGoal.RECONNAISSANCE_ONLY, 0.5


# =========================
# TIME TO COMPROMISE ESTIMATOR
# =========================
class TimeToCompromiseEstimator:
    """Estimates time until successful compromise."""
    
    def estimate(
        self,
        current_stage: AttackStage,
        skill_level: str,
        attack_speed: float  # attacks per minute
    ) -> int:
        """
        Estimate minutes until compromise.
        
        Returns:
            Estimated minutes (or -1 if already compromised)
        """
        # Base times by stage (minutes)
        stage_times = {
            AttackStage.RECONNAISSANCE: 30,
            AttackStage.INITIAL_ACCESS: 20,
            AttackStage.EXPLOITATION: 15,
            AttackStage.PRIVILEGE_ESCALATION: 10,
            AttackStage.PERSISTENCE: 5,
            AttackStage.DATA_EXFILTRATION: -1,  # Already compromised
            AttackStage.LATERAL_MOVEMENT: 5,
        }
        
        base_time = stage_times.get(current_stage, 30)
        
        if base_time == -1:
            return -1
        
        # Adjust for skill level
        skill_multipliers = {
            "novice": 2.0,
            "intermediate": 1.0,
            "advanced": 0.5,
            "automated": 0.3
        }
        
        multiplier = skill_multipliers.get(skill_level, 1.0)
        
        # Adjust for attack speed
        if attack_speed > 10:  # Very fast
            multiplier *= 0.7
        elif attack_speed < 1:  # Slow
            multiplier *= 1.5
        
        return int(base_time * multiplier)


# =========================
# DEFENSE RECOMMENDER
# =========================
class DefenseRecommender:
    """Recommends defensive countermeasures."""
    
    def recommend(
        self,
        predicted_vectors: List[Tuple[str, float]],
        current_stage: AttackStage,
        goal: AttackGoal
    ) -> List[str]:
        """Generate defense recommendations."""
        recommendations = []
        
        # Vector-specific defenses
        for vector, prob in predicted_vectors:
            if "sql" in vector.lower():
                recommendations.append("Enable WAF SQL injection rules")
                recommendations.append("Implement parameterized queries")
            elif "xss" in vector.lower():
                recommendations.append("Enable content security policy (CSP)")
                recommendations.append("Sanitize user inputs")
            elif "command" in vector.lower():
                recommendations.append("Disable command execution")
                recommendations.append("Implement input validation")
            elif "admin" in vector.lower():
                recommendations.append("Enforce MFA for admin access")
                recommendations.append("Review admin access logs")
        
        # Stage-specific defenses
        if current_stage == AttackStage.PRIVILEGE_ESCALATION:
            recommendations.append("Review privilege escalation paths")
            recommendations.append("Implement least privilege principle")
        elif current_stage == AttackStage.DATA_EXFILTRATION:
            recommendations.append("Monitor outbound traffic")
            recommendations.append("Enable DLP (Data Loss Prevention)")
        
        # Goal-specific defenses
        if goal == AttackGoal.CREDENTIAL_HARVESTING:
            recommendations.append("Implement account lockout policies")
            recommendations.append("Enable CAPTCHA on login")
        elif goal == AttackGoal.DATA_THEFT:
            recommendations.append("Encrypt sensitive data")
            recommendations.append("Implement access controls")
        
        # Remove duplicates and return
        return list(dict.fromkeys(recommendations))[:5]


# =========================
# ATTACK PREDICTION ENGINE
# =========================
class AttackPredictionEngine:
    """Main attack prediction engine."""
    
    def __init__(self):
        self.markov_predictor = MarkovChainPredictor()
        self.stage_classifier = AttackStageClassifier()
        self.goal_predictor = AttackGoalPredictor()
        self.time_estimator = TimeToCompromiseEstimator()
        self.defense_recommender = DefenseRecommender()
        
        # Track attack sequences per attacker
        self.sequences: Dict[str, AttackSequence] = {}
    
    def track_attack(
        self,
        attacker_id: str,
        attack_type: str,
        endpoint: str
    ):
        """Track an attack action."""
        if attacker_id not in self.sequences:
            self.sequences[attacker_id] = AttackSequence(attacker_id=attacker_id)
        
        sequence = self.sequences[attacker_id]
        sequence.add_action(attack_type, endpoint)
        
        # Learn from this transition
        if len(sequence.actions) > 1:
            self.markov_predictor.learn_transition(
                sequence.actions[-2],
                sequence.actions[-1]
            )
    
    def predict(
        self,
        attacker_id: str,
        skill_level: str = "intermediate",
        attack_speed: float = 1.0
    ) -> Optional[AttackPrediction]:
        """
        Generate attack prediction for attacker.
        
        Args:
            attacker_id: Attacker identifier
            skill_level: Attacker skill level
            attack_speed: Attacks per minute
            
        Returns:
            AttackPrediction or None if no data
        """
        if attacker_id not in self.sequences:
            return None
        
        sequence = self.sequences[attacker_id]
        
        if not sequence.actions:
            return None
        
        # Classify current stage
        current_stage = self.stage_classifier.classify_stage(sequence.actions)
        next_stage = self.stage_classifier.predict_next_stage(current_stage)
        
        # Predict next vectors
        current_action = sequence.actions[-1]
        prediction_result = self.markov_predictor.predict_next(current_action, top_k=3)
        next_vectors = prediction_result['top_predictions']
        
        # Predict goal
        goal, goal_confidence = self.goal_predictor.predict_goal(
            sequence.actions,
            sequence.endpoints,
            skill_level
        )
        
        # Estimate time to compromise
        time_to_compromise = self.time_estimator.estimate(
            current_stage,
            skill_level,
            attack_speed
        )
        
        # Generate defense recommendations
        defenses = self.defense_recommender.recommend(
            next_vectors,
            current_stage,
            goal
        )
        
        # Calculate threat level
        threat_level = self._calculate_threat_level(
            current_stage,
            goal,
            skill_level,
            time_to_compromise
        )
        
        return AttackPrediction(
            attacker_id=attacker_id,
            next_likely_vectors=next_vectors,
            predicted_goal=goal,
            goal_confidence=goal_confidence,
            current_stage=current_stage,
            next_stage=next_stage,
            time_to_compromise=time_to_compromise,
            recommended_defenses=defenses,
            threat_level=threat_level
        )
    
    def _calculate_threat_level(
        self,
        stage: AttackStage,
        goal: AttackGoal,
        skill_level: str,
        time_to_compromise: int
    ) -> str:
        """Calculate overall threat level."""
        score = 0
        
        # Stage scoring
        stage_scores = {
            AttackStage.RECONNAISSANCE: 1,
            AttackStage.INITIAL_ACCESS: 2,
            AttackStage.EXPLOITATION: 3,
            AttackStage.PRIVILEGE_ESCALATION: 4,
            AttackStage.PERSISTENCE: 5,
            AttackStage.DATA_EXFILTRATION: 5,
            AttackStage.LATERAL_MOVEMENT: 4,
        }
        score += stage_scores.get(stage, 1)
        
        # Goal scoring
        if goal in [AttackGoal.DATA_THEFT, AttackGoal.SYSTEM_COMPROMISE]:
            score += 2
        
        # Skill scoring
        if skill_level in ["advanced", "automated"]:
            score += 1
        
        # Time scoring
        if 0 < time_to_compromise < 10:
            score += 2
        elif 0 < time_to_compromise < 30:
            score += 1
        
        # Classify
        if score >= 7:
            return "critical"
        elif score >= 5:
            return "high"
        elif score >= 3:
            return "medium"
        else:
            return "low"
    
    def get_prediction_summary(self, attacker_id: str) -> Dict:
        """Get formatted prediction summary."""
        prediction = self.predict(attacker_id)
        
        if not prediction:
            return {"error": "No data for attacker"}
        
        return {
            "attacker_id": attacker_id,
            "current_stage": prediction.current_stage.value,
            "next_stage": prediction.next_stage.value if prediction.next_stage else None,
            "predicted_goal": prediction.predicted_goal.value,
            "goal_confidence": f"{prediction.goal_confidence:.1%}",
            "next_likely_vectors": [
                {"vector": v, "probability": f"{p:.1%}"}
                for v, p in prediction.next_likely_vectors
            ],
            "time_to_compromise_minutes": prediction.time_to_compromise,
            "threat_level": prediction.threat_level,
            "recommended_defenses": prediction.recommended_defenses
        }


# =========================
# GLOBAL INSTANCE
# =========================
_prediction_engine = AttackPredictionEngine()


def track_attack_for_prediction(attacker_id: str, attack_type: str, endpoint: str):
    """Track attack for prediction (convenience function)."""
    _prediction_engine.track_attack(attacker_id, attack_type, endpoint)


def get_attack_prediction(
    attacker_id: str,
    skill_level: str = "intermediate",
    attack_speed: float = 1.0
) -> Optional[AttackPrediction]:
    """Get attack prediction (convenience function)."""
    return _prediction_engine.predict(attacker_id, skill_level, attack_speed)


def get_prediction_summary(attacker_id: str) -> Dict:
    """Get prediction summary (convenience function)."""
    return _prediction_engine.get_prediction_summary(attacker_id)
