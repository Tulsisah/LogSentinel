from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from sqlalchemy import desc
from pydantic import BaseModel
from typing import Optional, List
from ..database import database, models
from datetime import datetime

router = APIRouter()

def get_db():
    db = database.SessionLocal()
    try:
        yield db
    finally:
        db.close()

class CustomRuleCreate(BaseModel):
    name: str
    description: str
    field_name: Optional[str] = None
    field: Optional[str] = None # Alias for frontend compatibility
    operator: Optional[str] = "contains" # contains, equals, regex, greater_than, startswith
    pattern: str
    threshold: Optional[int] = 1
    window_minutes: Optional[int] = 5
    same_ip: Optional[bool] = True
    severity: Optional[str] = "HIGH"
    threat_type: Optional[str] = "Custom Threat"
    mitre_technique: Optional[str] = "T1059"
    recommended_action: Optional[str] = "Investigate correlated events according to SOC guidelines."
    enabled: Optional[bool] = True

class CustomRuleUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    field_name: Optional[str] = None
    field: Optional[str] = None
    operator: Optional[str] = None
    pattern: Optional[str] = None
    threshold: Optional[int] = None
    window_minutes: Optional[int] = None
    same_ip: Optional[bool] = None
    severity: Optional[str] = None
    threat_type: Optional[str] = None
    mitre_technique: Optional[str] = None
    recommended_action: Optional[str] = None
    enabled: Optional[bool] = None

def serialize_rule(rule: models.CustomRule):
    return {
        "id": rule.id,
        "name": rule.name,
        "description": rule.description,
        "field_name": rule.field_name,
        "field": rule.field_name, # Alias for frontend
        "operator": rule.operator,
        "pattern": rule.pattern,
        "threshold": rule.threshold,
        "window_minutes": rule.window_minutes,
        "same_ip": rule.same_ip,
        "severity": rule.severity,
        "threat_type": rule.threat_type,
        "mitre_technique": rule.mitre_technique,
        "recommended_action": rule.recommended_action,
        "enabled": rule.enabled,
        "created_at": rule.created_at.isoformat() if rule.created_at else None
    }

@router.get("", include_in_schema=False)
@router.get("/")
def get_custom_rules(db: Session = Depends(get_db)):
    """Returns list of all user-defined custom detection rules."""
    rules = db.query(models.CustomRule).order_by(desc(models.CustomRule.created_at)).all()
    return [serialize_rule(r) for r in rules]

@router.post("", include_in_schema=False)
@router.post("/")
def create_custom_rule(payload: CustomRuleCreate, db: Session = Depends(get_db)):
    """Creates a new custom detection rule."""
    existing = db.query(models.CustomRule).filter(models.CustomRule.name == payload.name).first()
    if existing:
        raise HTTPException(status_code=400, detail=f"Rule with name '{payload.name}' already exists.")

    chosen_field = payload.field_name or payload.field or "message"

    rule = models.CustomRule(
        name=payload.name,
        description=payload.description,
        field_name=chosen_field,
        operator=payload.operator or "contains",
        pattern=payload.pattern,
        threshold=payload.threshold or 1,
        window_minutes=payload.window_minutes or 5,
        same_ip=payload.same_ip if payload.same_ip is not None else True,
        severity=payload.severity or "HIGH",
        threat_type=payload.threat_type or "Custom Threat",
        mitre_technique=payload.mitre_technique or "T1059",
        recommended_action=payload.recommended_action or "Review suspicious event and isolate host.",
        enabled=payload.enabled if payload.enabled is not None else True,
        created_at=datetime.utcnow()
    )
    db.add(rule)
    db.commit()
    db.refresh(rule)
    return serialize_rule(rule)

@router.put("/{rule_id}")
def update_custom_rule(rule_id: int, payload: CustomRuleUpdate, db: Session = Depends(get_db)):
    """Updates an existing custom detection rule."""
    rule = db.query(models.CustomRule).filter(models.CustomRule.id == rule_id).first()
    if not rule:
        raise HTTPException(status_code=404, detail="Rule not found.")

    update_data = payload.dict(exclude_unset=True)
    if "field" in update_data and not update_data.get("field_name"):
        update_data["field_name"] = update_data.pop("field")
    elif "field" in update_data:
        update_data.pop("field")

    for field, value in update_data.items():
        setattr(rule, field, value)

    db.commit()
    db.refresh(rule)
    return serialize_rule(rule)

@router.patch("/{rule_id}/toggle")
def toggle_custom_rule(rule_id: int, db: Session = Depends(get_db)):
    """Toggles rule enabled state."""
    rule = db.query(models.CustomRule).filter(models.CustomRule.id == rule_id).first()
    if not rule:
        raise HTTPException(status_code=404, detail="Rule not found.")

    rule.enabled = not rule.enabled
    db.commit()
    db.refresh(rule)
    return {"id": rule.id, "enabled": rule.enabled}

@router.delete("/{rule_id}")
def delete_custom_rule(rule_id: int, db: Session = Depends(get_db)):
    """Deletes a custom detection rule."""
    rule = db.query(models.CustomRule).filter(models.CustomRule.id == rule_id).first()
    if not rule:
        raise HTTPException(status_code=404, detail="Rule not found.")

    db.delete(rule)
    db.commit()
    return {"message": f"Rule '{rule.name}' deleted successfully."}
