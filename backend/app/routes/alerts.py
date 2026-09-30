from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from sqlalchemy import desc
from pydantic import BaseModel
from typing import Optional, List
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

class BulkStatusUpdate(BaseModel):
    alert_ids: List[int]
    status: str

@router.get("", include_in_schema=False)
@router.get("/")
def get_alerts(
    db: Session = Depends(get_db),
    status: Optional[str] = Query(None, description="Filter by status"),
    severity: Optional[str] = Query(None, description="Filter by severity"),
    threat_type: Optional[str] = Query(None, description="Filter by threat type"),
    source_ip: Optional[str] = Query(None, description="Filter by source IP")
):
    query = db.query(models.Alert)
    
    if status and status.upper() != "ALL":
        query = query.filter(models.Alert.status == status)
    if severity and severity.upper() != "ALL":
        query = query.filter(models.Alert.severity == severity.upper())
    if threat_type and threat_type.upper() != "ALL":
        query = query.filter(models.Alert.threat_type.ilike(f"%{threat_type}%"))
    if source_ip:
        query = query.filter(models.Alert.source_ip == source_ip)

    alerts = query.order_by(models.Alert.timestamp.desc()).all()
    return alerts

@router.post("/bulk-status")
def bulk_update_status(payload: BulkStatusUpdate, db: Session = Depends(get_db)):
    valid_statuses = ["New", "Investigating", "Resolved", "False Positive"]
    if payload.status not in valid_statuses:
        raise HTTPException(status_code=400, detail="Invalid status")

    db.query(models.Alert).filter(models.Alert.id.in_(payload.alert_ids)).update(
        {"status": payload.status}, synchronize_session=False
    )
    db.commit()
    return {"message": f"Updated {len(payload.alert_ids)} alert(s) to '{payload.status}'."}

@router.get("/{alert_id}")
def get_alert(alert_id: int, db: Session = Depends(get_db)):
    alert = db.query(models.Alert).filter(models.Alert.id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
        
    result = {c.name: getattr(alert, c.name) for c in alert.__table__.columns}
    if alert.original_log_id:
        log = db.query(models.LogEntry).filter(models.LogEntry.id == alert.original_log_id).first()
        if log:
            result['original_log'] = {c.name: getattr(log, c.name) for c in log.__table__.columns}
            
    return result

@router.put("/{alert_id}/status")
def update_alert_status(alert_id: int, status_update: StatusUpdate, db: Session = Depends(get_db)):
    alert = db.query(models.Alert).filter(models.Alert.id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    
    valid_statuses = ["New", "Investigating", "Resolved", "False Positive"]
    if status_update.status not in valid_statuses:
        raise HTTPException(status_code=400, detail="Invalid status")
        
    alert.status = status_update.status
    db.commit()
    db.refresh(alert)
    return alert

