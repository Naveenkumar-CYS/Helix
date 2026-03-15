"""
Forensic Timeline & Attack Replay Engine
Provides attack replay, forensic timeline visualization, and campaign analysis.
"""

from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
import json


# =========================
# ENUMS
# =========================
class EventType(Enum):
    """Timeline event types."""
    ATTACK = "attack"
    DECEPTION = "deception"
    CANARY_EXTRACTED = "canary_extracted"
    CANARY_USED = "canary_used"
    TOOL_DETECTED = "tool_detected"
    STAGE_TRANSITION = "stage_transition"
    ALERT_TRIGGERED = "alert_triggered"


class ReplaySpeed(Enum):
    """Replay speed options."""
    REALTIME = 1.0
    FAST_2X = 0.5
    FAST_5X = 0.2
    FAST_10X = 0.1
    INSTANT = 0.0


# =========================
# DATA MODELS
# =========================
@dataclass
class TimelineEvent:
    """Single event in forensic timeline."""
    timestamp: datetime
    event_type: EventType
    attacker_id: str
    title: str
    description: str
    endpoint: Optional[str] = None
    attack_type: Optional[str] = None
    payload: Optional[str] = None
    success: bool = False
    metadata: Dict = field(default_factory=dict)
    
    def to_dict(self) -> Dict:
        """Convert to dictionary."""
        return {
            "timestamp": self.timestamp.isoformat(),
            "event_type": self.event_type.value,
            "attacker_id": self.attacker_id,
            "title": self.title,
            "description": self.description,
            "endpoint": self.endpoint,
            "attack_type": self.attack_type,
            "payload": self.payload,
            "success": self.success,
            "metadata": self.metadata
        }


@dataclass
class AttackCampaignTimeline:
    """Complete timeline for an attack campaign."""
    attacker_id: str
    campaign_start: datetime
    campaign_end: datetime
    events: List[TimelineEvent] = field(default_factory=list)
    total_attacks: int = 0
    successful_attacks: int = 0
    tools_used: List[str] = field(default_factory=list)
    endpoints_targeted: List[str] = field(default_factory=list)
    canaries_extracted: int = 0
    canaries_reused: int = 0
    
    def add_event(self, event: TimelineEvent):
        """Add event to timeline."""
        self.events.append(event)
        
        # Update campaign end time
        if event.timestamp > self.campaign_end:
            self.campaign_end = event.timestamp
        
        # Update statistics
        if event.event_type == EventType.ATTACK:
            self.total_attacks += 1
            if event.success:
                self.successful_attacks += 1
            if event.endpoint and event.endpoint not in self.endpoints_targeted:
                self.endpoints_targeted.append(event.endpoint)
        
        elif event.event_type == EventType.CANARY_EXTRACTED:
            self.canaries_extracted += 1
        
        elif event.event_type == EventType.CANARY_USED:
            self.canaries_reused += 1
        
        elif event.event_type == EventType.TOOL_DETECTED:
            tool = event.metadata.get("tool")
            if tool and tool not in self.tools_used:
                self.tools_used.append(tool)
    
    def get_duration(self) -> timedelta:
        """Get campaign duration."""
        return self.campaign_end - self.campaign_start
    
    def get_attack_rate(self) -> float:
        """Get attacks per minute."""
        duration_minutes = self.get_duration().total_seconds() / 60
        if duration_minutes > 0:
            return self.total_attacks / duration_minutes
        return 0.0


# =========================
# FORENSIC TIMELINE BUILDER
# =========================
class ForensicTimelineBuilder:
    """Builds forensic timelines from attack data."""
    
    def __init__(self):
        self.timelines: Dict[str, AttackCampaignTimeline] = {}
    
    def record_attack(
        self,
        attacker_id: str,
        attack_type: str,
        endpoint: str,
        payload: str,
        success: bool,
        timestamp: Optional[datetime] = None
    ):
        """Record an attack event."""
        if timestamp is None:
            timestamp = datetime.now()
        
        # Create timeline if doesn't exist
        if attacker_id not in self.timelines:
            self.timelines[attacker_id] = AttackCampaignTimeline(
                attacker_id=attacker_id,
                campaign_start=timestamp,
                campaign_end=timestamp
            )
        
        # Create event
        event = TimelineEvent(
            timestamp=timestamp,
            event_type=EventType.ATTACK,
            attacker_id=attacker_id,
            title=f"{attack_type} on {endpoint}",
            description=f"Attack: {attack_type}",
            endpoint=endpoint,
            attack_type=attack_type,
            payload=payload,
            success=success
        )
        
        self.timelines[attacker_id].add_event(event)
    
    def record_deception(
        self,
        attacker_id: str,
        deception_type: str,
        description: str,
        timestamp: Optional[datetime] = None
    ):
        """Record a deception event."""
        if timestamp is None:
            timestamp = datetime.now()
        
        if attacker_id not in self.timelines:
            self.timelines[attacker_id] = AttackCampaignTimeline(
                attacker_id=attacker_id,
                campaign_start=timestamp,
                campaign_end=timestamp
            )
        
        event = TimelineEvent(
            timestamp=timestamp,
            event_type=EventType.DECEPTION,
            attacker_id=attacker_id,
            title=f"Deception: {deception_type}",
            description=description,
            metadata={"deception_type": deception_type}
        )
        
        self.timelines[attacker_id].add_event(event)
    
    def record_canary_extraction(
        self,
        attacker_id: str,
        canary_type: str,
        canary_value: str,
        source: str,
        timestamp: Optional[datetime] = None
    ):
        """Record canary token extraction."""
        if timestamp is None:
            timestamp = datetime.now()
        
        if attacker_id not in self.timelines:
            self.timelines[attacker_id] = AttackCampaignTimeline(
                attacker_id=attacker_id,
                campaign_start=timestamp,
                campaign_end=timestamp
            )
        
        event = TimelineEvent(
            timestamp=timestamp,
            event_type=EventType.CANARY_EXTRACTED,
            attacker_id=attacker_id,
            title=f"Canary Extracted: {canary_type}",
            description=f"Attacker extracted {canary_type} from {source}",
            metadata={
                "canary_type": canary_type,
                "canary_value": canary_value,
                "source": source
            }
        )
        
        self.timelines[attacker_id].add_event(event)
    
    def record_canary_usage(
        self,
        attacker_id: str,
        canary_value: str,
        usage_location: str,
        timestamp: Optional[datetime] = None
    ):
        """Record canary token usage."""
        if timestamp is None:
            timestamp = datetime.now()
        
        if attacker_id not in self.timelines:
            self.timelines[attacker_id] = AttackCampaignTimeline(
                attacker_id=attacker_id,
                campaign_start=timestamp,
                campaign_end=timestamp
            )
        
        event = TimelineEvent(
            timestamp=timestamp,
            event_type=EventType.CANARY_USED,
            attacker_id=attacker_id,
            title="Canary Token Reused",
            description=f"Attacker used extracted canary at {usage_location}",
            metadata={
                "canary_value": canary_value,
                "usage_location": usage_location
            }
        )
        
        self.timelines[attacker_id].add_event(event)
    
    def record_tool_detection(
        self,
        attacker_id: str,
        tool_name: str,
        confidence: float,
        timestamp: Optional[datetime] = None
    ):
        """Record attack tool detection."""
        if timestamp is None:
            timestamp = datetime.now()
        
        if attacker_id not in self.timelines:
            self.timelines[attacker_id] = AttackCampaignTimeline(
                attacker_id=attacker_id,
                campaign_start=timestamp,
                campaign_end=timestamp
            )
        
        event = TimelineEvent(
            timestamp=timestamp,
            event_type=EventType.TOOL_DETECTED,
            attacker_id=attacker_id,
            title=f"Tool Detected: {tool_name}",
            description=f"Detected use of {tool_name} (confidence: {confidence:.0%})",
            metadata={
                "tool": tool_name,
                "confidence": confidence
            }
        )
        
        self.timelines[attacker_id].add_event(event)
    
    def get_timeline(self, attacker_id: str) -> Optional[AttackCampaignTimeline]:
        """Get timeline for attacker."""
        return self.timelines.get(attacker_id)
    
    def get_timeline_events(
        self,
        attacker_id: str,
        event_type: Optional[EventType] = None
    ) -> List[TimelineEvent]:
        """Get timeline events, optionally filtered by type."""
        timeline = self.get_timeline(attacker_id)
        if not timeline:
            return []
        
        events = timeline.events
        if event_type:
            events = [e for e in events if e.event_type == event_type]
        
        return sorted(events, key=lambda x: x.timestamp)
    
    def generate_timeline_html(self, attacker_id: str) -> str:
        """Generate HTML timeline visualization."""
        timeline = self.get_timeline(attacker_id)
        if not timeline:
            return "<p>No timeline data available</p>"
        
        events = sorted(timeline.events, key=lambda x: x.timestamp)
        
        html = f"""
        <div class="forensic-timeline">
            <h3>Attack Campaign Timeline - {attacker_id}</h3>
            <div class="timeline-stats">
                <span>Duration: {timeline.get_duration()}</span>
                <span>Total Attacks: {timeline.total_attacks}</span>
                <span>Success Rate: {timeline.successful_attacks}/{timeline.total_attacks}</span>
                <span>Attack Rate: {timeline.get_attack_rate():.2f}/min</span>
            </div>
            <div class="timeline-events">
        """
        
        for event in events:
            event_class = event.event_type.value
            success_class = "success" if event.success else "failed"
            
            html += f"""
                <div class="timeline-event {event_class} {success_class}">
                    <div class="event-time">{event.timestamp.strftime('%H:%M:%S')}</div>
                    <div class="event-content">
                        <div class="event-title">{event.title}</div>
                        <div class="event-description">{event.description}</div>
                    </div>
                </div>
            """
        
        html += """
            </div>
        </div>
        """
        
        return html


# =========================
# ATTACK REPLAY ENGINE
# =========================
class AttackReplayEngine:
    """Replays attack campaigns with playback controls."""
    
    def __init__(self, timeline_builder: ForensicTimelineBuilder):
        self.timeline_builder = timeline_builder
    
    def generate_replay_script(
        self,
        attacker_id: str,
        speed: ReplaySpeed = ReplaySpeed.FAST_5X
    ) -> List[Dict]:
        """
        Generate replay script with timing.
        
        Returns:
            List of replay steps with delays
        """
        timeline = self.timeline_builder.get_timeline(attacker_id)
        if not timeline:
            return []
        
        events = sorted(timeline.events, key=lambda x: x.timestamp)
        if not events:
            return []
        
        replay_script = []
        start_time = events[0].timestamp
        
        for i, event in enumerate(events):
            # Calculate delay from previous event
            if i == 0:
                delay_ms = 0
            else:
                time_diff = (event.timestamp - events[i-1].timestamp).total_seconds()
                delay_ms = int(time_diff * 1000 * speed.value)
            
            replay_script.append({
                "step": i + 1,
                "delay_ms": delay_ms,
                "event": event.to_dict(),
                "elapsed_time": str(event.timestamp - start_time)
            })
        
        return replay_script
    
    def generate_narrative(self, attacker_id: str) -> str:
        """Generate narrative description of attack campaign."""
        timeline = self.timeline_builder.get_timeline(attacker_id)
        if not timeline:
            return "No attack data available."
        
        narrative = f"Attack Campaign Analysis for {attacker_id}\n\n"
        narrative += f"Campaign Duration: {timeline.get_duration()}\n"
        narrative += f"Total Attacks: {timeline.total_attacks}\n"
        narrative += f"Successful Attacks: {timeline.successful_attacks}\n\n"
        
        narrative += "Attack Progression:\n"
        
        events = sorted(timeline.events, key=lambda x: x.timestamp)
        for i, event in enumerate(events, 1):
            elapsed = event.timestamp - timeline.campaign_start
            narrative += f"{i}. [{elapsed}] {event.title}\n"
            narrative += f"   {event.description}\n"
            
            if event.success:
                narrative += "   ✓ Successful\n"
            
            if event.event_type == EventType.CANARY_EXTRACTED:
                narrative += "   ⚠ Data exfiltration detected\n"
            
            narrative += "\n"
        
        # Summary
        narrative += "\nKey Findings:\n"
        if timeline.tools_used:
            narrative += f"- Tools detected: {', '.join(timeline.tools_used)}\n"
        if timeline.canaries_extracted > 0:
            narrative += f"- Canary tokens extracted: {timeline.canaries_extracted}\n"
        if timeline.canaries_reused > 0:
            narrative += f"- Canary tokens reused: {timeline.canaries_reused}\n"
        narrative += f"- Endpoints targeted: {', '.join(timeline.endpoints_targeted)}\n"
        
        return narrative


# =========================
# CAMPAIGN COMPARISON
# =========================
class CampaignComparator:
    """Compares attack campaigns to find similarities."""
    
    def compare_campaigns(
        self,
        timeline1: AttackCampaignTimeline,
        timeline2: AttackCampaignTimeline
    ) -> Dict:
        """
        Compare two attack campaigns.
        
        Returns:
            Similarity metrics
        """
        # Attack type similarity
        types1 = {e.attack_type for e in timeline1.events if e.attack_type}
        types2 = {e.attack_type for e in timeline2.events if e.attack_type}
        
        if types1 and types2:
            type_similarity = len(types1 & types2) / len(types1 | types2)
        else:
            type_similarity = 0.0
        
        # Endpoint similarity
        endpoints1 = set(timeline1.endpoints_targeted)
        endpoints2 = set(timeline2.endpoints_targeted)
        
        if endpoints1 and endpoints2:
            endpoint_similarity = len(endpoints1 & endpoints2) / len(endpoints1 | endpoints2)
        else:
            endpoint_similarity = 0.0
        
        # Tool similarity
        tools1 = set(timeline1.tools_used)
        tools2 = set(timeline2.tools_used)
        
        if tools1 and tools2:
            tool_similarity = len(tools1 & tools2) / len(tools1 | tools2)
        else:
            tool_similarity = 0.0
        
        # Overall similarity
        overall_similarity = (type_similarity + endpoint_similarity + tool_similarity) / 3
        
        return {
            "attacker1": timeline1.attacker_id,
            "attacker2": timeline2.attacker_id,
            "attack_type_similarity": type_similarity,
            "endpoint_similarity": endpoint_similarity,
            "tool_similarity": tool_similarity,
            "overall_similarity": overall_similarity,
            "likely_same_actor": overall_similarity > 0.7
        }


# =========================
# GLOBAL INSTANCE
# =========================
_forensic_timeline = ForensicTimelineBuilder()
_replay_engine = AttackReplayEngine(_forensic_timeline)
_campaign_comparator = CampaignComparator()


def record_attack_event(
    attacker_id: str,
    attack_type: str,
    endpoint: str,
    payload: str,
    success: bool
):
    """Record attack event (convenience function)."""
    _forensic_timeline.record_attack(attacker_id, attack_type, endpoint, payload, success)


def record_canary_extraction(attacker_id: str, canary_type: str, canary_value: str, source: str):
    """Record canary extraction (convenience function)."""
    _forensic_timeline.record_canary_extraction(attacker_id, canary_type, canary_value, source)


def record_tool_detection(attacker_id: str, tool_name: str, confidence: float):
    """Record tool detection (convenience function)."""
    _forensic_timeline.record_tool_detection(attacker_id, tool_name, confidence)


def get_attack_timeline(attacker_id: str) -> Optional[AttackCampaignTimeline]:
    """Get attack timeline (convenience function)."""
    return _forensic_timeline.get_timeline(attacker_id)


def generate_replay_script(attacker_id: str, speed: ReplaySpeed = ReplaySpeed.FAST_5X) -> List[Dict]:
    """Generate replay script (convenience function)."""
    return _replay_engine.generate_replay_script(attacker_id, speed)


def generate_attack_narrative(attacker_id: str) -> str:
    """Generate attack narrative (convenience function)."""
    return _replay_engine.generate_narrative(attacker_id)


def get_timeline_html(attacker_id: str) -> str:
    """Get timeline HTML (convenience function)."""
    return _forensic_timeline.generate_timeline_html(attacker_id)
