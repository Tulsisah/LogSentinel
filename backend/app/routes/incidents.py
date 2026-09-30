from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from sqlalchemy import desc
from pydantic import BaseModel
from typing import List, Optional
from ..database import database, models

router = APIRouter()

def get_db():
    db = database.SessionLocal()
    try:
        yield db
    finally:
        db.close()

class StatusUpdate(BaseModel):
    status: str

@router.get("", include_in_schema=False)
@router.get("/")
def get_incidents(db: Session = Depends(get_db)):
    """
    Returns list of all correlated security incidents ordered by recency and risk,
    with embedded attack progression timeline and MITRE framework tactics.
    """
    incidents = db.query(models.Incident).order_by(desc(models.Incident.created_at)).all()
    res = []
    for inc in incidents:
        alerts = (
            db.query(models.Alert)
            .filter(models.Alert.incident_id == inc.id)
            .order_by(models.Alert.timestamp.asc())
            .all()
        )
        timeline = []
        tactics = []
        users = set()
        if inc.target_username and inc.target_username != "Unknown":
            users.add(inc.target_username)
        for idx, a in enumerate(alerts, 1):
            if a.username and a.username != "Unknown":
                users.add(a.username)
            if a.mitre_technique and a.mitre_technique not in tactics:
                tactics.append(a.mitre_technique)
            timeline.append({
                "step": idx,
                "stage": a.threat_type,
                "event": a.event,
                "severity": a.severity,
                "timestamp": a.timestamp.isoformat() if a.timestamp else None,
                "source_ip": a.source_ip,
                "description": a.detection_reason,
                "technique": a.mitre_technique,
                "alert_id": a.id
            })

        first_seen = alerts[0].timestamp.isoformat() if alerts and alerts[0].timestamp else (inc.created_at.isoformat() if inc.created_at else None)
        last_seen = alerts[-1].timestamp.isoformat() if alerts and alerts[-1].timestamp else (inc.created_at.isoformat() if inc.created_at else None)

        res.append({
            "id": inc.id,
            "title": inc.title,
            "severity": inc.severity,
            "risk_score": inc.risk_score,
            "risk_level": inc.risk_level,
            "source_ip": inc.source_ip,
            "primary_ip": inc.source_ip,
            "target_username": inc.target_username,
            "affected_users": list(users),
            "attack_type": inc.attack_type,
            "summary": inc.explanation.splitlines()[0] if inc.explanation else inc.title,
            "explanation": inc.explanation,
            "recommended_action": inc.recommended_action,
            "status": inc.status,
            "created_at": inc.created_at.isoformat() if inc.created_at else None,
            "first_seen": first_seen,
            "last_seen": last_seen,
            "event_count": inc.event_count or len(alerts),
            "attack_timeline": timeline,
            "mitre_tactics": tactics if tactics else ["Initial Access", "Lateral Movement"]
        })
    return res

@router.get("/{incident_id}")
def get_incident_details(incident_id: int, db: Session = Depends(get_db)):
    """
    Fetches full incident details including chronological timeline of correlated alerts and raw logs.
    """
    incident = db.query(models.Incident).filter(models.Incident.id == incident_id).first()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found.")

    # Correlated alerts
    alerts = (
        db.query(models.Alert)
        .filter(models.Alert.incident_id == incident_id)
        .order_by(models.Alert.timestamp.asc())
        .all()
    )

    # Correlated logs by entity IP or username
    log_query = db.query(models.LogEntry)
    if incident.source_ip and incident.source_ip != "Unknown":
        log_query = log_query.filter(models.LogEntry.source_ip == incident.source_ip)
    elif incident.target_username and incident.target_username != "Unknown":
        log_query = log_query.filter(models.LogEntry.username == incident.target_username)
        
    related_logs = log_query.order_by(models.LogEntry.timestamp.asc()).limit(50).all()

    # Build chronological timeline nodes
    timeline = []
    for a in alerts:
        timeline.append({
            "id": a.id,
            "type": "alert",
            "timestamp": a.timestamp,
            "title": a.event,
            "threat_type": a.threat_type,
            "severity": a.severity,
            "risk_score": a.risk_score,
            "reason": a.detection_reason,
            "mitre": a.mitre_technique,
            "action": a.recommended_action
        })

    return {
        "incident": incident,
        "timeline": timeline,
        "alerts_count": len(alerts),
        "related_logs": related_logs
    }

@router.put("/{incident_id}/status")
def update_incident_status(incident_id: int, payload: StatusUpdate, db: Session = Depends(get_db)):
    incident = db.query(models.Incident).filter(models.Incident.id == incident_id).first()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found.")

    status_map = {
        "new": "New",
        "open": "New",
        "investigating": "Investigating",
        "contained": "Resolved",
        "resolved": "Resolved",
        "false positive": "False Positive",
        "false_positive": "False Positive"
    }
    normalized_status = status_map.get(payload.status.strip().lower(), payload.status.strip())
    valid_statuses = ["New", "Investigating", "Resolved", "False Positive"]
    if normalized_status not in valid_statuses:
        raise HTTPException(status_code=400, detail=f"Invalid status. Must be one of: {', '.join(valid_statuses)}")

    incident.status = normalized_status
    
    # Also cascade status update to linked alerts
    db.query(models.Alert).filter(models.Alert.incident_id == incident_id).update({"status": normalized_status}, synchronize_session=False)
    
    db.commit()
    db.refresh(incident)
    return incident
