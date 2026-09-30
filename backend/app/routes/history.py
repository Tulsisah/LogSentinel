from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from sqlalchemy import desc
from ..database import database, models

router = APIRouter()

def get_db():
    db = database.SessionLocal()
    try:
        yield db
    finally:
        db.close()

@router.get("", include_in_schema=False)
@router.get("/")
def get_analysis_history(db: Session = Depends(get_db)):
    """Returns all stored analysis sessions."""
    sessions = db.query(models.AnalysisSession).order_by(desc(models.AnalysisSession.created_at)).all()
    return sessions

@router.get("/{session_id}")
def get_session_details(session_id: int, db: Session = Depends(get_db)):
    """Fetches details, alerts, and stats for a specific analysis session."""
    session = db.query(models.AnalysisSession).filter(models.AnalysisSession.id == session_id).first()
    if not session:
        raise HTTPException(status_code=404, detail="Analysis session not found.")

    alerts = db.query(models.Alert).filter(models.Alert.analysis_id == session_id).all()
    incidents = db.query(models.Incident).filter(models.Incident.analysis_id == session_id).all()
    logs_count = db.query(models.LogEntry).filter(models.LogEntry.analysis_id == session_id).count()

    return {
        "session": session,
        "logs_count": logs_count,
        "alerts": alerts,
        "incidents": incidents
    }

@router.delete("/{session_id}")
def delete_session(session_id: int, db: Session = Depends(get_db)):
    """Deletes an analysis session and its associated logs, alerts, and incidents."""
    session = db.query(models.AnalysisSession).filter(models.AnalysisSession.id == session_id).first()
    if not session:
        raise HTTPException(status_code=404, detail="Analysis session not found.")

    db.query(models.Alert).filter(models.Alert.analysis_id == session_id).delete()
    db.query(models.Incident).filter(models.Incident.analysis_id == session_id).delete()
    db.query(models.LogEntry).filter(models.LogEntry.analysis_id == session_id).delete()
    db.delete(session)
    db.commit()

    return {"message": f"Analysis session #{session_id} and associated telemetry deleted."}
