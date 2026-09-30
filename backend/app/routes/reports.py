from fastapi import APIRouter, Depends, Response
from fastapi.responses import JSONResponse, PlainTextResponse
from fastapi.encoders import jsonable_encoder
from sqlalchemy.orm import Session
from sqlalchemy import func, desc, or_
from typing import Optional
from io import StringIO
import csv
import json
from datetime import datetime
from ..database import database, models
from ..services.ai_analyzer import generate_ai_analysis
from .ips import is_private_ip, get_ip_reputation_label

router = APIRouter()

def get_db():
    db = database.SessionLocal()
    try:
        yield db
    finally:
        db.close()

@router.get("/summary")
def get_report_summary(db: Session = Depends(get_db)):
    """
    Assembles a comprehensive SOC Executive Report.
    """
    total_logs = db.query(models.LogEntry).count()
    total_alerts = db.query(models.Alert).count()
    critical_alerts = db.query(models.Alert).filter(models.Alert.severity == "CRITICAL").count()
    high_alerts = db.query(models.Alert).filter(models.Alert.severity == "HIGH").count()
    total_incidents = db.query(models.Incident).count()
    top_risk = db.query(func.max(models.Alert.risk_score)).scalar() or 0.0

    first_log = db.query(func.min(models.LogEntry.timestamp)).scalar()
    last_log = db.query(func.max(models.LogEntry.timestamp)).scalar()
    period = f"{first_log.strftime('%Y-%m-%d %H:%M') if first_log else 'N/A'} to {last_log.strftime('%Y-%m-%d %H:%M') if last_log else 'N/A'}"

    # Severity Summary
    severity_counts = dict(db.query(models.Alert.severity, func.count(models.Alert.id)).group_by(models.Alert.severity).all())

    # Top Suspicious IPs with full metadata
    top_ips_query = (
        db.query(models.Alert.source_ip, func.count(models.Alert.id))
        .filter(models.Alert.source_ip != "Unknown")
        .group_by(models.Alert.source_ip)
        .order_by(func.count(models.Alert.id).desc())
        .limit(5)
        .all()
    )
    top_ips = []
    for ip_val, threat_cnt in top_ips_query:
        ip_total_events = db.query(models.LogEntry).filter(models.LogEntry.source_ip == ip_val).count()
        ip_failed_logins = db.query(models.LogEntry).filter(
            models.LogEntry.source_ip == ip_val,
            or_(models.LogEntry.auth_status == "FAILED", models.LogEntry.event_type.ilike("%failed%"))
        ).count()
        ip_max_risk = db.query(func.max(models.Alert.risk_score)).filter(models.Alert.source_ip == ip_val).scalar() or 0.0
        top_ips.append({
            "ip": ip_val,
            "reputation_label": get_ip_reputation_label(ip_max_risk, threat_cnt),
            "request_count": ip_total_events,
            "total_events": ip_total_events,
            "failed_logins": ip_failed_logins,
            "risk_score": round(ip_max_risk, 1),
            "threats": threat_cnt
        })

    # Top Threat Types
    top_threats_query = (
        db.query(models.Alert.threat_type, func.count(models.Alert.id))
        .group_by(models.Alert.threat_type)
        .order_by(func.count(models.Alert.id).desc())
        .limit(6)
        .all()
    )
    top_threats = [{"type": t[0], "count": t[1]} for t in top_threats_query]

    # Critical Incidents (Serialized dicts for clean JSON output)
    incidents = db.query(models.Incident).order_by(desc(models.Incident.risk_score)).limit(5).all()
    serialized_incidents = []
    for inc in incidents:
        serialized_incidents.append({
            "id": inc.id,
            "title": inc.title,
            "severity": inc.severity,
            "risk_score": inc.risk_score,
            "risk_level": inc.risk_level,
            "source_ip": inc.source_ip,
            "target_username": inc.target_username,
            "attack_type": inc.attack_type,
            "explanation": inc.explanation,
            "recommended_action": inc.recommended_action,
            "status": inc.status,
            "created_at": inc.created_at.isoformat() if inc.created_at else None,
            "event_count": inc.event_count
        })

    # AI Analysis / Executive Summary
    logs = db.query(models.LogEntry).order_by(desc(models.LogEntry.timestamp)).limit(200).all()
    alerts = db.query(models.Alert).order_by(desc(models.Alert.timestamp)).limit(100).all()
    logs_data = [{c.name: getattr(l, c.name) for c in l.__table__.columns} for l in logs]
    alerts_data = [{c.name: getattr(a, c.name) for c in a.__table__.columns} for a in alerts]
    incidents_data = serialized_incidents

    ai_data = generate_ai_analysis(
        {"total_logs": total_logs, "suspicious_events": total_alerts, "critical_alerts": critical_alerts, "high_risk_events": high_alerts},
        alerts_data, logs_data, incidents_data
    )

    return {
        "report_id": f"SOC-REP-{datetime.utcnow().strftime('%Y%m%d-%H%M')}",
        "generated_at": datetime.utcnow().isoformat(),
        "analysis_period": period,
        "metrics": {
            "total_logs": total_logs,
            "total_alerts": total_alerts,
            "critical_alerts": critical_alerts,
            "critical_threats": critical_alerts,
            "high_alerts": high_alerts,
            "total_incidents": total_incidents,
            "overall_risk_score": round(top_risk, 1),
            "severity_summary": severity_counts
        },
        "top_suspicious_ips": top_ips,
        "top_threats": top_threats,
        "critical_incidents": serialized_incidents,
        "executive_summary": ai_data.get("executive_summary"),
        "confirmed_evidence": ai_data.get("confirmed_evidence"),
        "suspicious_indicators": ai_data.get("suspicious_indicators"),
        "possible_interpretation": ai_data.get("possible_interpretation"),
        "potential_impact": ai_data.get("potential_impact"),
        "recommended_actions": ai_data.get("recommended_actions") or ai_data.get("recommended_defensive_actions")
    }

@router.get("/export")
def export_report(format: str = "json", db: Session = Depends(get_db)):
    """
    Exports security findings in JSON or CSV format.
    """
    alerts = db.query(models.Alert).order_by(desc(models.Alert.timestamp)).all()

    if format.lower() == "csv":
        output = StringIO()
        writer = csv.writer(output)
        writer.writerow([
            "ID", "Timestamp", "Source IP", "Username", "Event",
            "Threat Type", "Severity", "Risk Score", "Risk Level",
            "Detection Rule", "MITRE Technique", "Status", "Detection Reason"
        ])
        for a in alerts:
            writer.writerow([
                a.id,
                a.timestamp.strftime("%Y-%m-%d %H:%M:%S") if a.timestamp else "",
                a.source_ip,
                a.username,
                a.event,
                a.threat_type,
                a.severity,
                a.risk_score,
                a.risk_level,
                a.detection_rule,
                a.mitre_technique,
                a.status,
                a.detection_reason
            ])
        csv_content = output.getvalue()
        return Response(
            content=csv_content,
            media_type="text/csv",
            headers={"Content-Disposition": f"attachment; filename=soc_alerts_report_{datetime.utcnow().strftime('%Y%m%d')}.csv"}
        )

    # JSON export
    summary = get_report_summary(db)
    return JSONResponse(
        content=jsonable_encoder(summary),
        headers={"Content-Disposition": f"attachment; filename=soc_executive_report_{datetime.utcnow().strftime('%Y%m%d')}.json"}
    )
