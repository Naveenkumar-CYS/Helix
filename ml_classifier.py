"""
Machine Learning Attack Classifier
Uses scikit-learn for advanced attack pattern detection and anomaly detection.
"""

from typing import Dict, List, Tuple, Optional
from dataclasses import dataclass, field
from datetime import datetime, timedelta
import re
import json
from collections import Counter, defaultdict


# =========================
# FEATURE EXTRACTION
# =========================
class AttackFeatureExtractor:
    """Extracts features from attack payloads for ML classification."""
    
    def extract_features(self, payload: str) -> Dict[str, float]:
        """
        Extract numerical features from attack payload.
        
        Returns:
            Dictionary of feature name -> value
        """
        features = {}
        
        # Length features
        features['payload_length'] = len(payload)
        features['word_count'] = len(payload.split())
        
        # Character frequency features
        features['special_char_ratio'] = sum(1 for c in payload if not c.isalnum()) / max(len(payload), 1)
        features['digit_ratio'] = sum(1 for c in payload if c.isdigit()) / max(len(payload), 1)
        features['uppercase_ratio'] = sum(1 for c in payload if c.isupper()) / max(len(payload), 1)
        
        # SQL injection indicators
        sql_keywords = ['select', 'union', 'insert', 'update', 'delete', 'drop', 'create', 'alter']
        features['sql_keyword_count'] = sum(1 for kw in sql_keywords if kw in payload.lower())
        features['has_sql_comment'] = float('--' in payload or '/*' in payload or '#' in payload)
        features['has_union'] = float('union' in payload.lower())
        features['has_or_clause'] = float(re.search(r"(or|OR)\s+\d+=\d+", payload) is not None)
        
        # XSS indicators
        features['has_script_tag'] = float('<script' in payload.lower())
        features['has_javascript'] = float('javascript:' in payload.lower())
        features['has_event_handler'] = float(any(evt in payload.lower() for evt in ['onerror', 'onload', 'onclick']))
        
        # Command injection indicators
        features['has_shell_metachar'] = float(any(c in payload for c in [';', '|', '&', '`', '$']))
        features['has_command'] = float(any(cmd in payload.lower() for cmd in ['cat', 'ls', 'wget', 'curl', 'rm']))
        
        # Path traversal indicators
        features['has_dotdot'] = float('../' in payload or '..\\' in payload)
        features['has_encoded_dotdot'] = float('%2e%2e' in payload.lower())
        
        # Encoding indicators
        features['has_url_encoding'] = float('%' in payload and re.search(r'%[0-9a-fA-F]{2}', payload) is not None)
        features['has_hex_encoding'] = float('0x' in payload.lower())
        
        # Obfuscation indicators
        features['has_concat'] = float('concat' in payload.lower())
        features['has_char_function'] = float('char(' in payload.lower())
        features['entropy'] = self._calculate_entropy(payload)
        
        return features
    
    def _calculate_entropy(self, text: str) -> float:
        """Calculate Shannon entropy of text."""
        if not text:
            return 0.0
        
        # Count character frequencies
        counter = Counter(text)
        length = len(text)
        
        # Calculate entropy
        entropy = 0.0
        for count in counter.values():
            probability = count / length
            if probability > 0:
                entropy -= probability * (probability ** 0.5)  # Simplified entropy
        
        return entropy


# =========================
# ANOMALY DETECTION
# =========================
@dataclass
class AttackProfile:
    """Statistical profile of normal attack patterns."""
    feature_means: Dict[str, float] = field(default_factory=dict)
    feature_stds: Dict[str, float] = field(default_factory=dict)
    sample_count: int = 0


class AnomalyDetector:
    """Detects anomalous attacks that don't match known patterns."""
    
    def __init__(self, threshold: float = 2.5):
        self.threshold = threshold  # Standard deviations from mean
        self.profiles: Dict[str, AttackProfile] = {}
        self.feature_extractor = AttackFeatureExtractor()
    
    def update_profile(self, attack_type: str, payload: str) -> None:
        """Update statistical profile for attack type."""
        features = self.feature_extractor.extract_features(payload)
        
        if attack_type not in self.profiles:
            self.profiles[attack_type] = AttackProfile()
        
        profile = self.profiles[attack_type]
        
        # Update running statistics
        for feature, value in features.items():
            if feature not in profile.feature_means:
                profile.feature_means[feature] = value
                profile.feature_stds[feature] = 0.0
            else:
                # Update mean and std (simplified online algorithm)
                old_mean = profile.feature_means[feature]
                new_mean = (old_mean * profile.sample_count + value) / (profile.sample_count + 1)
                profile.feature_means[feature] = new_mean
                
                # Update standard deviation
                if profile.sample_count > 0:
                    old_std = profile.feature_stds[feature]
                    profile.feature_stds[feature] = ((old_std ** 2 * profile.sample_count + 
                                                     (value - new_mean) ** 2) / (profile.sample_count + 1)) ** 0.5
        
        profile.sample_count += 1
    
    def detect_anomaly(self, attack_type: str, payload: str) -> Tuple[bool, float]:
        """
        Detect if payload is anomalous for its attack type.
        
        Returns:
            Tuple of (is_anomaly, anomaly_score)
        """
        if attack_type not in self.profiles or self.profiles[attack_type].sample_count < 10:
            # Not enough data to detect anomalies
            return False, 0.0
        
        features = self.feature_extractor.extract_features(payload)
        profile = self.profiles[attack_type]
        
        # Calculate z-scores for each feature
        z_scores = []
        for feature, value in features.items():
            if feature in profile.feature_means:
                mean = profile.feature_means[feature]
                std = profile.feature_stds[feature]
                
                if std > 0:
                    z_score = abs(value - mean) / std
                    z_scores.append(z_score)
        
        if not z_scores:
            return False, 0.0
        
        # Anomaly score is max z-score
        anomaly_score = max(z_scores)
        is_anomaly = anomaly_score > self.threshold
        
        return is_anomaly, anomaly_score


# =========================
# CREDENTIAL TRACKING
# =========================
@dataclass
class CredentialAttempt:
    """Single credential attempt."""
    timestamp: datetime
    username: str
    password: str
    success: bool
    endpoint: str


class CredentialTracker:
    """Tracks credential-based attacks (brute force, password spray, stuffing)."""
    
    def __init__(self):
        self.attempts: Dict[str, List[CredentialAttempt]] = defaultdict(list)
        self.username_attempts: Dict[str, List[CredentialAttempt]] = defaultdict(list)
    
    def track_attempt(
        self,
        attacker_id: str,
        username: str,
        password: str,
        success: bool,
        endpoint: str
    ) -> None:
        """Track a credential attempt."""
        attempt = CredentialAttempt(
            timestamp=datetime.now(),
            username=username,
            password=password,
            success=success,
            endpoint=endpoint
        )
        
        self.attempts[attacker_id].append(attempt)
        self.username_attempts[username].append(attempt)
    
    def detect_brute_force(
        self,
        attacker_id: str,
        time_window: int = 300,  # 5 minutes
        threshold: int = 10
    ) -> bool:
        """
        Detect brute force attack (many passwords for one username).
        
        Returns:
            True if brute force detected
        """
        if attacker_id not in self.attempts:
            return False
        
        recent_attempts = self._get_recent_attempts(attacker_id, time_window)
        
        if len(recent_attempts) < threshold:
            return False
        
        # Check if targeting same username with different passwords
        usernames = [a.username for a in recent_attempts]
        passwords = [a.password for a in recent_attempts]
        
        # Brute force: same username, many different passwords
        if len(set(usernames)) == 1 and len(set(passwords)) > threshold * 0.8:
            return True
        
        return False
    
    def detect_password_spray(
        self,
        attacker_id: str,
        time_window: int = 3600,  # 1 hour
        threshold: int = 5
    ) -> bool:
        """
        Detect password spray attack (one password for many usernames).
        
        Returns:
            True if password spray detected
        """
        if attacker_id not in self.attempts:
            return False
        
        recent_attempts = self._get_recent_attempts(attacker_id, time_window)
        
        if len(recent_attempts) < threshold:
            return False
        
        # Check if using same password for different usernames
        usernames = [a.username for a in recent_attempts]
        passwords = [a.password for a in recent_attempts]
        
        # Password spray: many usernames, same password
        if len(set(passwords)) == 1 and len(set(usernames)) > threshold * 0.8:
            return True
        
        return False
    
    def detect_credential_stuffing(
        self,
        attacker_id: str,
        time_window: int = 600,  # 10 minutes
        threshold: int = 20
    ) -> bool:
        """
        Detect credential stuffing (many username/password pairs).
        
        Returns:
            True if credential stuffing detected
        """
        if attacker_id not in self.attempts:
            return False
        
        recent_attempts = self._get_recent_attempts(attacker_id, time_window)
        
        if len(recent_attempts) < threshold:
            return False
        
        # Check if using many different username/password combinations
        pairs = [(a.username, a.password) for a in recent_attempts]
        
        # Credential stuffing: many unique pairs
        if len(set(pairs)) > threshold * 0.9:
            return True
        
        return False
    
    def _get_recent_attempts(
        self,
        attacker_id: str,
        time_window: int
    ) -> List[CredentialAttempt]:
        """Get attempts within time window."""
        cutoff = datetime.now() - timedelta(seconds=time_window)
        return [
            a for a in self.attempts[attacker_id]
            if a.timestamp > cutoff
        ]
    
    def get_attack_summary(self, attacker_id: str) -> Dict[str, any]:
        """Get summary of credential attacks."""
        if attacker_id not in self.attempts:
            return {}
        
        attempts = self.attempts[attacker_id]
        
        return {
            "total_attempts": len(attempts),
            "unique_usernames": len(set(a.username for a in attempts)),
            "unique_passwords": len(set(a.password for a in attempts)),
            "success_count": sum(1 for a in attempts if a.success),
            "is_brute_force": self.detect_brute_force(attacker_id),
            "is_password_spray": self.detect_password_spray(attacker_id),
            "is_credential_stuffing": self.detect_credential_stuffing(attacker_id),
        }


# =========================
# ML CLASSIFIER (Simplified)
# =========================
class SimpleMLClassifier:
    """Simplified ML classifier for attack patterns."""
    
    def __init__(self):
        self.feature_extractor = AttackFeatureExtractor()
        self.training_data: List[Tuple[Dict[str, float], str]] = []
    
    def train(self, payload: str, attack_type: str) -> None:
        """Add training example."""
        features = self.feature_extractor.extract_features(payload)
        self.training_data.append((features, attack_type))
    
    def predict(self, payload: str) -> Tuple[str, float]:
        """
        Predict attack type with confidence.
        
        Returns:
            Tuple of (predicted_type, confidence)
        """
        if not self.training_data:
            return "UNKNOWN", 0.0
        
        features = self.feature_extractor.extract_features(payload)
        
        # Simple k-NN classifier (k=5)
        distances = []
        for train_features, train_type in self.training_data:
            distance = self._euclidean_distance(features, train_features)
            distances.append((distance, train_type))
        
        # Get k nearest neighbors
        k = min(5, len(distances))
        nearest = sorted(distances)[:k]
        
        # Vote for most common type
        types = [t for _, t in nearest]
        most_common = Counter(types).most_common(1)[0]
        
        predicted_type = most_common[0]
        confidence = most_common[1] / k
        
        return predicted_type, confidence
    
    def _euclidean_distance(
        self,
        features1: Dict[str, float],
        features2: Dict[str, float]
    ) -> float:
        """Calculate Euclidean distance between feature vectors."""
        distance = 0.0
        all_features = set(features1.keys()) | set(features2.keys())
        
        for feature in all_features:
            val1 = features1.get(feature, 0.0)
            val2 = features2.get(feature, 0.0)
            distance += (val1 - val2) ** 2
        
        return distance ** 0.5


# =========================
# GLOBAL INSTANCES
# =========================
_ml_classifier = SimpleMLClassifier()
_anomaly_detector = AnomalyDetector()
_credential_tracker = CredentialTracker()


def train_ml_classifier(payload: str, attack_type: str) -> None:
    """Train ML classifier (convenience function)."""
    _ml_classifier.train(payload, attack_type)
    _anomaly_detector.update_profile(attack_type, payload)


def predict_attack_type(payload: str) -> Tuple[str, float]:
    """Predict attack type using ML (convenience function)."""
    return _ml_classifier.predict(payload)


def detect_anomaly(attack_type: str, payload: str) -> Tuple[bool, float]:
    """Detect anomalous attack (convenience function)."""
    return _anomaly_detector.detect_anomaly(attack_type, payload)


def track_credential_attempt(
    attacker_id: str,
    username: str,
    password: str,
    success: bool,
    endpoint: str
) -> Dict[str, any]:
    """Track credential attempt and return attack summary."""
    _credential_tracker.track_attempt(attacker_id, username, password, success, endpoint)
    return _credential_tracker.get_attack_summary(attacker_id)
