import ipaddress
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from sqlalchemy import func, desc, or_
from ..database import database, models
from typing import List, Dict, Any

router = APIRouter()

def get_db():
    db = database.SessionLocal()
    try:
        yield db
    finally:
        db.close()

def is_private_ip(ip_str: str) -> bool:
    """Checks if an IP address belongs to RFC 1918 private address space."""
    try:
        ip = ipaddress.ip_address(ip_str.strip())
        return ip.is_private or ip.is_loopback
    except:
        return False

def get_ip_reputation_label(risk_score: float, threat_count: int) -> str:
    """
    Returns responsible, non-defamatory risk labels:
    Clean, Monitored, Suspicious, High Risk, Potentially Malicious.
    """
    if risk_score >= 85 or threat_count >= 5:
        return "Potentially Malicious"
    elif risk_score >= 65 or threat_count >= 3:
        return "High Risk"
    elif risk_score >= 40 or threat_count >= 1:
        return "Suspicious"
    elif threat_count > 0:
        return "Monitored"
    return "Standard Baseline"

@router.get("", include_in_schema=False)
@router.get("/")
def get_ip_analysis_list(db: Session = Depends(get_db)):
    """
    Computes comprehensive IP profiles for all active source IPs in the database.
    """
    # Group logs by source IP
    source_ips = (
        db.query(models.LogEntry.source_ip)
        .filter(models.LogEntry.source_ip != "Unknown", models.LogEntry.source_ip != None)
        .distinct()
        .all()
    )

    results = []
    for (ip,) in source_ips:
        total_events = db.query(models.LogEntry).filter(models.LogEntry.source_ip == ip).count()
        if total_events == 0:
            continue

        failed_logins = db.query(models.LogEntry).filter(
            models.LogEntry.source_ip == ip,
            or_(models.LogEntry.auth_status == "FAILED", models.LogEntry.event_type.ilike("%failed%"))
        ).count()

        successful_logins = db.query(models.LogEntry).filter(
            models.LogEntry.source_ip == ip,
            or_(models.LogEntry.auth_status == "SUCCESS", models.LogEntry.event_type.ilike("%success%"))
        ).count()

        # Alerts for this IP
        alerts = db.query(models.Alert).filter(models.Alert.source_ip == ip).all()
        threat_count = len(alerts)

        severities = [a.severity for a in alerts if a.severity]
        if "CRITICAL" in severities:
            highest_severity = "CRITICAL"
        elif "HIGH" in severities:
            highest_severity = "HIGH"
        elif "MEDIUM" in severities:
            highest_severity = "MEDIUM"
        elif "LOW" in severities:
            highest_severity = "LOW"
        else:
            highest_severity = "INFO"

        risk_scores = [a.risk_score for a in alerts if a.risk_score is not None]
        risk_score = round(max(risk_scores, default=0.0), 1)

        # First and Last seen timestamps
        first_seen = db.query(func.min(models.LogEntry.timestamp)).filter(models.LogEntry.source_ip == ip).scalar()
        last_seen = db.query(func.max(models.LogEntry.timestamp)).filter(models.LogEntry.source_ip == ip).scalar()

        # Related usernames
        usernames = (
            db.query(models.LogEntry.username)
            .filter(models.LogEntry.source_ip == ip, models.LogEntry.username != "Unknown")
            .distinct()
            .limit(6)
            .all()
        )
        related_users = [u[0] for u in usernames if u[0]]

        # Classification
        ip_type = "Internal (Private)" if is_private_ip(ip) else "External (Public)"
        reputation = get_ip_reputation_label(risk_score, threat_count)

        results.append({
            "ip": ip,
            "ip_type": ip_type,
            "is_internal": is_private_ip(ip),
            "reputation_label": reputation,
            "total_events": total_events,
            "request_count": total_events, # Alias for frontend
            "failed_logins": failed_logins,
            "successful_logins": successful_logins,
            "threat_count": threat_count,
            "highest_severity": highest_severity,
            "risk_score": risk_score,
            "first_seen": first_seen,
            "last_seen": last_seen,
            "related_usernames": related_users,
            "target_users": related_users # Alias for frontend
        })

    # Sort descending by risk score and threat count
    results.sort(key=lambda x: (x["risk_score"], x["threat_count"]), reverse=True)
    return results

@router.get("/{ip}")
def get_single_ip_profile(ip: str, db: Session = Depends(get_db)):
    """
    Returns full forensic profile of a specific IP address including related events.
    """
    logs = db.query(models.LogEntry).filter(models.LogEntry.source_ip == ip).order_by(desc(models.LogEntry.timestamp)).limit(100).all()
    if not logs:
        raise HTTPException(status_code=404, detail=f"No telemetry found for IP '{ip}'.")

    alerts = db.query(models.Alert).filter(models.Alert.source_ip == ip).order_by(desc(models.Alert.timestamp)).all()

    failed_logins = sum(1 for l in logs if l.auth_status == "FAILED" or "fail" in (l.event_type or "").lower())
    successful_logins = sum(1 for l in logs if l.auth_status == "SUCCESS" or "succ" in (l.event_type or "").lower())
    risk_scores = [a.risk_score for a in alerts if a.risk_score is not None]
    risk_score = round(max(risk_scores, default=0.0), 1)

    target_users = list(dict.fromkeys([l.username for l in logs if l.username and l.username != "Unknown"]))

    return {
        "ip": ip,
        "is_internal": is_private_ip(ip),
        "ip_type": "Internal (Private)" if is_private_ip(ip) else "External (Public)",
        "reputation_label": get_ip_reputation_label(risk_score, len(alerts)),
        "risk_score": risk_score,
        "total_events": len(logs),
        "request_count": len(logs),
        "threat_count": len(alerts),
        "failed_logins": failed_logins,
        "successful_logins": successful_logins,
        "first_seen": logs[-1].timestamp if logs else None,
        "last_seen": logs[0].timestamp if logs else None,
        "related_usernames": target_users,
        "target_users": target_users,
        "alerts": alerts,
        "associated_alerts": alerts,
        "recent_logs": logs[:30],
        "associated_logs": logs[:30]
    }
