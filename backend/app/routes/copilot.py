from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from sqlalchemy import desc
from pydantic import BaseModel
from typing import List, Dict, Any, Optional
from ..database import database, models
from ..services.ai_analyzer import generate_ai_analysis, answer_copilot_query

router = APIRouter()

def get_db():
    db = database.SessionLocal()
    try:
        yield db
    finally:
        db.close()

class ChatRequest(BaseModel):
    question: str

@router.post("/chat")
def copilot_chat(payload: ChatRequest, db: Session = Depends(get_db)):
    """
    Interactive SOC Copilot endpoint that analyzes live database context
    and answers security questions (e.g. 'What happened?', 'Which IP is most suspicious?').
    """
    logs = db.query(models.LogEntry).order_by(desc(models.LogEntry.timestamp)).limit(200).all()
    alerts = db.query(models.Alert).order_by(desc(models.Alert.timestamp)).limit(100).all()
    incidents = db.query(models.Incident).order_by(desc(models.Incident.created_at)).limit(20).all()

    logs_data = [{c.name: getattr(l, c.name) for c in l.__table__.columns} for l in logs]
    alerts_data = [{c.name: getattr(a, c.name) for c in a.__table__.columns} for a in alerts]
    incidents_data = [{c.name: getattr(i, c.name) for c in i.__table__.columns} for i in incidents]

    stats = {
        "total_logs": len(logs_data),
        "suspicious_events": len(alerts_data),
        "critical_alerts": len([a for a in alerts_data if a.get("severity") == "CRITICAL"])
    }

    answer = answer_copilot_query(payload.question, logs_data, alerts_data, incidents_data, stats)

    suggested_queries = [
        "What happened?",
        "Which IP is most suspicious?",
        "Is this a brute-force attack?",
        "Show critical events.",
        "Why is this event high risk?",
        "What should the analyst do?"
    ]

    return {
        "answer": answer,
        "suggested_queries": [s for s in suggested_queries if s.lower() != payload.question.lower()][:4]
    }

@router.get("/ai-summary")
def get_ai_summary(db: Session = Depends(get_db)):
    """
    Generates structured AI SOC analysis distinguishing Confirmed Evidence,
    Suspicious Indicators, and Possible Interpretation.
    """
    logs = db.query(models.LogEntry).order_by(desc(models.LogEntry.timestamp)).limit(300).all()
    alerts = db.query(models.Alert).order_by(desc(models.Alert.timestamp)).limit(100).all()
    incidents = db.query(models.Incident).order_by(desc(models.Incident.created_at)).limit(20).all()

    logs_data = [{c.name: getattr(l, c.name) for c in l.__table__.columns} for l in logs]
    alerts_data = [{c.name: getattr(a, c.name) for c in a.__table__.columns} for a in alerts]
    incidents_data = [{c.name: getattr(i, c.name) for c in i.__table__.columns} for i in incidents]

    stats = {
        "total_logs": len(logs_data),
        "suspicious_events": len(alerts_data),
        "critical_alerts": len([a for a in alerts_data if a.get("severity") == "CRITICAL"]),
        "high_risk_events": len([a for a in alerts_data if a.get("severity") == "HIGH"])
    }

    return generate_ai_analysis(stats, alerts_data, logs_data, incidents_data)
