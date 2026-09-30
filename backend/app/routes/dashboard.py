from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from sqlalchemy import func, desc, or_
from ..database import database, models
from datetime import datetime, timedelta

router = APIRouter()

def get_db():
    db = database.SessionLocal()
    try:
        yield db
    finally:
        db.close()

@router.get("", include_in_schema=False)
@router.get("/")
def get_dashboard_stats(db: Session = Depends(get_db)):
    total_logs = db.query(models.LogEntry).count()
    total_alerts = db.query(models.Alert).count()
    
    critical_alerts = db.query(models.Alert).filter(models.Alert.severity == "CRITICAL").count()
    high_alerts = db.query(models.Alert).filter(models.Alert.severity == "HIGH").count()
    unique_ips = db.query(models.LogEntry.source_ip).distinct().count()

    # Failed and Successful logins
    failed_logins = db.query(models.LogEntry).filter(
        or_(
            models.LogEntry.auth_status == "FAILED",
            models.LogEntry.event_type.ilike("%failed%"),
            models.LogEntry.event_type.ilike("%login_fail%")
        )
    ).count()

    successful_logins = db.query(models.LogEntry).filter(
        or_(
            models.LogEntry.auth_status == "SUCCESS",
            models.LogEntry.event_type.ilike("%successful%"),
            models.LogEntry.event_type.ilike("%login_succ%")
        )
    ).count()

    account_lockouts = db.query(models.LogEntry).filter(
        or_(
            models.LogEntry.event_type == "account_lockout",
            models.LogEntry.message.ilike("%locked out%"),
            models.LogEntry.message.ilike("%account locked%")
        )
    ).count()

    anomalies_count = db.query(models.Alert).filter(
        or_(
            models.Alert.threat_type == "Statistical Anomaly",
            models.Alert.threat_type.ilike("%anomaly%")
        )
    ).count()

    # Overall Risk Score calculation
    top_risk_alert = db.query(models.Alert).order_by(models.Alert.risk_score.desc()).first()
    overall_risk_score = round(top_risk_alert.risk_score, 1) if top_risk_alert and top_risk_alert.risk_score else (
        85.0 if critical_alerts > 0 else (65.0 if high_alerts > 0 else (30.0 if total_alerts > 0 else 0.0))
    )
    
    if overall_risk_score >= 81.0:
        overall_risk_level = "Critical"
    elif overall_risk_score >= 61.0:
        overall_risk_level = "High"
    elif overall_risk_score >= 41.0:
        overall_risk_level = "Medium"
    elif overall_risk_score >= 21.0:
        overall_risk_level = "Moderate"
    else:
        overall_risk_level = "Low"

    # 1. Severity Distribution
    severity_counts = db.query(models.Alert.severity, func.count(models.Alert.id)).group_by(models.Alert.severity).all()
    severity_chart = [{"name": s[0], "value": s[1]} for s in severity_counts]

    # 2. Top Suspicious IPs
    top_ips = (
        db.query(models.Alert.source_ip, func.count(models.Alert.id))
        .filter(models.Alert.source_ip != "Unknown")
        .group_by(models.Alert.source_ip)
        .order_by(func.count(models.Alert.id).desc())
        .limit(6)
        .all()
    )
    top_ips_chart = [{"ip": ip[0], "count": ip[1]} for ip in top_ips]

    # 3. Attack Type Distribution
    attack_types = (
        db.query(models.Alert.threat_type, func.count(models.Alert.id))
        .group_by(models.Alert.threat_type)
        .order_by(func.count(models.Alert.id).desc())
        .limit(8)
        .all()
    )
    attack_type_chart = [{"type": a[0], "count": a[1]} for a in attack_types]

    # 4. Events Over Time Timeline (Grouped by hour or 10-minute slice)
    recent_logs = db.query(models.LogEntry).order_by(models.LogEntry.timestamp.desc()).limit(500).all()
    timeline_dict = {}
    for log in recent_logs:
        if log.timestamp:
            bucket = log.timestamp.strftime("%H:%M")
            if bucket not in timeline_dict:
                timeline_dict[bucket] = {"time": bucket, "events": 0, "threats": 0}
            timeline_dict[bucket]["events"] += 1

    recent_alerts = db.query(models.Alert).order_by(models.Alert.timestamp.desc()).limit(200).all()
    for a in recent_alerts:
        if a.timestamp:
            bucket = a.timestamp.strftime("%H:%M")
            if bucket in timeline_dict:
                timeline_dict[bucket]["threats"] += 1
            else:
                timeline_dict[bucket] = {"time": bucket, "events": 1, "threats": 1}

    events_over_time = sorted(list(timeline_dict.values()), key=lambda x: x["time"])[-15:]

    # 5. Authentication Success vs Failure
    auth_chart = [
        {"name": "Successful Logins", "value": successful_logins, "color": "#10b981"},
        {"name": "Failed Logins", "value": failed_logins, "color": "#ef4444"},
        {"name": "Account Lockouts", "value": account_lockouts, "color": "#f59e0b"}
    ]

    # 6. Top Targeted Usernames
    top_users_query = (
        db.query(models.LogEntry.username, func.count(models.LogEntry.id))
        .filter(models.LogEntry.username != "Unknown", models.LogEntry.username != "-")
        .group_by(models.LogEntry.username)
        .order_by(func.count(models.LogEntry.id).desc())
        .limit(6)
        .all()
    )
    top_users_chart = [{"username": u[0], "count": u[1]} for u in top_users_query]

    # 7. Event Categories Breakdown
    event_cats_query = (
        db.query(models.LogEntry.event_type, func.count(models.LogEntry.id))
        .group_by(models.LogEntry.event_type)
        .order_by(func.count(models.LogEntry.id).desc())
        .limit(7)
        .all()
    )
    event_categories_chart = [{"category": e[0], "count": e[1]} for e in event_cats_query]

    return {
        "summary": {
            "total_logs": total_logs,
            "events_analyzed": total_logs,
            "suspicious_events": total_alerts,
            "threats_detected": total_alerts,
            "critical_alerts": critical_alerts,
            "high_risk_events": high_alerts,
            "unique_ips": unique_ips,
            "failed_logins": failed_logins,
            "successful_logins": successful_logins,
            "account_lockouts": account_lockouts,
            "anomalies": anomalies_count,
            "overall_risk_score": overall_risk_score,
            "overall_risk_level": overall_risk_level
        },
        "charts": {
            "severity": severity_chart,
            "top_ips": top_ips_chart,
            "attack_types": attack_type_chart,
            "events_over_time": events_over_time,
            "auth_chart": auth_chart,
            "top_users": top_users_chart,
            "event_categories": event_categories_chart
        }
    }

@router.get("/auth-analytics")
def get_auth_analytics(db: Session = Depends(get_db)):
    """
    Dedicated endpoint for Authentication Analysis (Checklist Item 7).
    """
    failed_logins = db.query(models.LogEntry).filter(
        or_(
            models.LogEntry.auth_status == "FAILED",
            models.LogEntry.event_type.ilike("%failed%"),
            models.LogEntry.event_type.ilike("%login_fail%")
        )
    ).count()

    successful_logins = db.query(models.LogEntry).filter(
        or_(
            models.LogEntry.auth_status == "SUCCESS",
            models.LogEntry.event_type.ilike("%successful%"),
            models.LogEntry.event_type.ilike("%login_succ%")
        )
    ).count()

    total_attempts = failed_logins + successful_logins
    failure_percentage = round((failed_logins / total_attempts * 100), 1) if total_attempts > 0 else 0.0

    account_lockouts = db.query(models.LogEntry).filter(
        or_(
            models.LogEntry.event_type == "account_lockout",
            models.LogEntry.message.ilike("%locked out%"),
            models.LogEntry.message.ilike("%account locked%")
        )
    ).count()

    # Most targeted usernames in authentication attempts
    targeted_users = (
        db.query(models.LogEntry.username, func.count(models.LogEntry.id))
        .filter(
            or_(
                models.LogEntry.auth_status == "FAILED",
                models.LogEntry.event_type.ilike("%failed%")
            ),
            models.LogEntry.username != "Unknown"
        )
        .group_by(models.LogEntry.username)
        .order_by(func.count(models.LogEntry.id).desc())
        .limit(8)
        .all()
    )

    # Most active authentication IPs
    active_auth_ips = (
        db.query(models.LogEntry.source_ip, func.count(models.LogEntry.id))
        .filter(
            models.LogEntry.source_ip != "Unknown",
            or_(
                models.LogEntry.auth_status.in_(["SUCCESS", "FAILED"]),
                models.LogEntry.event_type.ilike("%login%")
            )
        )
        .group_by(models.LogEntry.source_ip)
        .order_by(func.count(models.LogEntry.id).desc())
        .limit(8)
        .all()
    )

    # Compromise detections (successful login after failed logins)
    compromise_alerts = db.query(models.Alert).filter(
        models.Alert.threat_type == "Account Compromise"
    ).all()

    return {
        "total_attempts": total_attempts,
        "successful_logins": successful_logins,
        "failed_logins": failed_logins,
        "failure_percentage": failure_percentage,
        "account_lockouts": account_lockouts,
        "targeted_users": [{"username": u[0], "failed_attempts": u[1]} for u in targeted_users],
        "active_ips": [{"ip": i[0], "attempts": i[1]} for i in active_auth_ips],
        "compromised_accounts": [
            {
                "username": a.username,
                "ip": a.source_ip,
                "timestamp": a.timestamp,
                "reason": a.detection_reason
            }
            for a in compromise_alerts
        ]
    }

