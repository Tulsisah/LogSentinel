from typing import List, Optional
from sqlalchemy.orm import Session
from ..database import models
import datetime

def correlate_incidents(alerts: List[models.Alert], db: Session, analysis_id: Optional[int] = None) -> List[models.Incident]:
    """
    Correlates security alerts by source IP, target user, and temporal proximity
    into unified, multi-stage Incidents with chronological timelines.
    """
    if not alerts:
        return []

    # Group alerts by entity (source_ip primarily, fallback to username)
    entity_groups = {}
    for alert in alerts:
        key = alert.source_ip if alert.source_ip and alert.source_ip != "Unknown" else (alert.username or "Unassigned")
        if key not in entity_groups:
            entity_groups[key] = []
        entity_groups[key].append(alert)

    created_incidents = []

    for key, group in entity_groups.items():
        # Sort chronologically
        sorted_alerts = sorted(group, key=lambda a: a.timestamp or datetime.datetime.min)
        
        # Determine highest severity
        severities = [a.severity for a in sorted_alerts]
        if "CRITICAL" in severities:
            highest_sev = "CRITICAL"
        elif "HIGH" in severities:
            highest_sev = "HIGH"
        elif "MEDIUM" in severities:
            highest_sev = "MEDIUM"
        else:
            highest_sev = "LOW"

        # Threat types involved
        threat_types = list(dict.fromkeys([a.threat_type for a in sorted_alerts if a.threat_type]))
        primary_threat = threat_types[0] if threat_types else "Security Anomaly"
        
        # Calculate composite incident risk score
        max_score = max([a.risk_score or 0.0 for a in sorted_alerts], default=50.0)
        # Sequence multiplier: +3 per additional correlated event up to +15
        sequence_bonus = min(len(sorted_alerts) - 1, 5) * 3.0
        final_score = min(max_score + sequence_bonus, 100.0)
        
        if final_score >= 81.0:
            risk_level = "Critical"
        elif final_score >= 61.0:
            risk_level = "High"
        elif final_score >= 41.0:
            risk_level = "Medium"
        elif final_score >= 21.0:
            risk_level = "Moderate"
        else:
            risk_level = "Low"

        # Identify source IP and target username
        source_ip = next((a.source_ip for a in sorted_alerts if a.source_ip and a.source_ip != "Unknown"), key)
        target_username = next((a.username for a in sorted_alerts if a.username and a.username != "Unknown"), "Unknown")

        # Synthesize Title
        if len(threat_types) > 1:
            title = f"Multi-Stage Incident: {' -> '.join(threat_types[:3])}"
            attack_type = "Multi-Stage Attack Chain"
        else:
            title = f"{primary_threat} Incident targeting {target_username}"
            attack_type = primary_threat

        # Build chronological explanation narrative
        narrative_lines = [
            f"Automated incident correlation synthesized {len(sorted_alerts)} security detection(s) involving entity '{key}'.",
            "Chronological Attack Progression:"
        ]
        for idx, a in enumerate(sorted_alerts, 1):
            ts_str = a.timestamp.strftime("%Y-%m-%d %H:%M:%S") if a.timestamp else "N/A"
            narrative_lines.append(
                f"  [{idx}] {ts_str} UTC: {a.event} ({a.severity}) - {a.detection_reason}"
            )
            
        explanation = "\n".join(narrative_lines)

        # Consolidate recommended actions
        actions = list(dict.fromkeys([a.recommended_action for a in sorted_alerts if a.recommended_action]))
        if not actions:
            actions = ["Quarantine affected host, revoke active user sessions, and review SIEM telemetry."]
        recommended_action = " | ".join(actions)

        # Create Incident record
        incident = models.Incident(
            title=title,
            severity=highest_sev,
            risk_score=final_score,
            risk_level=risk_level,
            source_ip=source_ip,
            target_username=target_username,
            attack_type=attack_type,
            explanation=explanation,
            recommended_action=recommended_action,
            status="New",
            created_at=datetime.datetime.utcnow(),
            analysis_id=analysis_id,
            event_count=len(sorted_alerts)
        )
        db.add(incident)
        db.flush() # Populate incident.id

        # Associate each alert with the incident
        for a in sorted_alerts:
            a.incident_id = incident.id
            a.risk_level = risk_level

        created_incidents.append(incident)

    db.commit()
    return created_incidents
