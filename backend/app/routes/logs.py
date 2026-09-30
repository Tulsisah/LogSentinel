from fastapi import APIRouter, UploadFile, File, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from sqlalchemy import or_, and_, desc, asc
from pydantic import BaseModel
from typing import Optional, List
from ..database import database, models
from ..services.parser import parse_log_file
from ..detection.rules import analyze_rules, calculate_risk
from ..ml.anomaly import run_anomaly_detection
from ..services.correlator import correlate_incidents
import base64
import pandas as pd
import json
from datetime import datetime

router = APIRouter()

MAX_FILE_SIZE = 25 * 1024 * 1024  # 25 MB limit
ALLOWED_EXTENSIONS = {".log", ".txt", ".csv", ".json"}

def get_db():
    db = database.SessionLocal()
    try:
        yield db
    finally:
        db.close()

def decode_payload_text(raw_text: str, is_base64: bool = False) -> str:
    """
    Safely decode log content. When is_base64 is True or the string is base64 encoded,
    decodes it back to raw log lines. This prevents Cloud WAFs (like Render/Cloudflare)
    from blocking uploads that contain SQL Injection or Path Traversal attack signatures.
    """
    if not raw_text:
        return ""
    if is_base64:
        try:
            return base64.b64decode(raw_text).decode('utf-8', errors='replace')
        except Exception:
            return raw_text
    # Auto-detect base64 string
    cleaned = raw_text.strip()
    if len(cleaned) > 40 and "\n" not in cleaned and len(cleaned) % 4 == 0:
        try:
            candidate = base64.b64decode(cleaned, validate=True).decode('utf-8', errors='replace')
            if "\n" in candidate or " " in candidate:
                return candidate
        except Exception:
            pass
    return raw_text

class PasteLogRequest(BaseModel):
    content: str
    filename: Optional[str] = "manual_paste.log"
    is_base64: Optional[bool] = False

@router.post("/upload")
async def upload_log_file(file: UploadFile = File(...), db: Session = Depends(get_db)):
    # 1. Validate extension
    filename = file.filename or "unknown.log"
    ext = "." + filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
    if ext not in ALLOWED_EXTENSIONS:
        raise HTTPException(
            status_code=400,
            detail=f"Unsupported file type '{ext}'. Allowed extensions: {', '.join(ALLOWED_EXTENSIONS)}"
        )

    # 2. Read and validate file size
    content = await file.read()
    if len(content) > MAX_FILE_SIZE:
        raise HTTPException(
            status_code=413,
            detail=f"File exceeds maximum allowed size of 25MB (File size: {len(content) / (1024*1024):.2f}MB)"
        )

    try:
        content_str = content.decode('utf-8', errors='replace')
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Failed to decode file as UTF-8: {str(e)}")

    content_str = decode_payload_text(content_str)

    # 3. Parse
    df = parse_log_file(content_str, filename)
    if df.empty:
        raise HTTPException(status_code=400, detail="Could not parse log file or file contains no recognizable records.")

    return await process_dataframe(df, filename, db)

@router.post("/paste")
async def paste_log_content(payload: PasteLogRequest, db: Session = Depends(get_db)):
    if not payload.content.strip():
        raise HTTPException(status_code=400, detail="Log content cannot be empty.")

    decoded_text = decode_payload_text(payload.content, payload.is_base64 or False)

    if len(decoded_text.encode('utf-8')) > MAX_FILE_SIZE:
        raise HTTPException(status_code=413, detail="Pasted content exceeds 25MB limit.")

    df = parse_log_file(decoded_text, payload.filename or "pasted_logs.txt")
    if df.empty:
        raise HTTPException(status_code=400, detail="Could not extract any valid log entries from the pasted text.")

    return await process_dataframe(df, payload.filename or "pasted_logs.txt", db)

@router.post("/sample")
async def load_sample_logs(db: Session = Depends(get_db)):
    import sys
    import os
    sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
    import sample_logs_generator

    csv_content = sample_logs_generator.generate_sample_logs_csv()
    df = parse_log_file(csv_content, "sample.csv")
    return await process_dataframe(df, "sample_attack_scenario.csv", db)

async def process_dataframe(df: pd.DataFrame, filename: str, db: Session):
    # Fresh analysis: Clear previous telemetry so that dashboard and views reflect only the active file's analysis
    db.query(models.Alert).delete()
    db.query(models.Incident).delete()
    db.query(models.LogEntry).delete()
    db.query(models.AnalysisSession).delete()
    db.commit()

    # 1. Create AnalysisSession record
    analysis = models.AnalysisSession(
        filename=filename,
        created_at=datetime.utcnow(),
        log_count=len(df),
        status="Processing"
    )
    db.add(analysis)
    db.flush()

    # 2. ML Anomaly Detection (Explainable)
    df = run_anomaly_detection(df)

    # 3. Fetch active custom rules from DB
    custom_rules_db = db.query(models.CustomRule).filter(models.CustomRule.enabled == True).all()
    custom_rules = [
        {
            "name": r.name,
            "description": r.description,
            "field_name": r.field_name,
            "operator": r.operator,
            "pattern": r.pattern,
            "threshold": r.threshold,
            "window_minutes": r.window_minutes,
            "same_ip": r.same_ip,
            "severity": r.severity,
            "threat_type": r.threat_type,
            "mitre_technique": r.mitre_technique,
            "recommended_action": r.recommended_action,
            "enabled": r.enabled
        }
        for r in custom_rules_db
    ]

    # Helper safe converters
    def safe_int(v):
        if v is None or pd.isna(v):
            return None
        try:
            return int(float(v))
        except (ValueError, TypeError):
            return None

    def safe_str(v, default=None):
        if v is None or pd.isna(v) or str(v).lower() in ['none', 'nan', '<na>']:
            return default
        return str(v).strip()

    # 4. Batch Save Log Entries to DB
    log_records = []
    for _, row in df.iterrows():
        log = models.LogEntry(
            timestamp=row['timestamp'],
            source_ip=safe_str(row.get('source_ip'), 'Unknown'),
            destination_ip=safe_str(row.get('destination_ip')),
            username=safe_str(row.get('username'), 'Unknown'),
            hostname=safe_str(row.get('hostname')),
            event_type=safe_str(row.get('event_type'), 'system_event'),
            http_method=safe_str(row.get('http_method')),
            url_path=safe_str(row.get('url_path')),
            status_code=safe_int(row.get('status_code')),
            port=safe_int(row.get('port')),
            protocol=safe_str(row.get('protocol')),
            auth_status=safe_str(row.get('auth_status')),
            severity=safe_str(row.get('severity', 'INFO'), 'INFO').upper(),
            message=safe_str(row.get('message', ''), ''),
            raw_log=safe_str(row.get('raw_log', ''), ''),
            user_agent=safe_str(row.get('user_agent')),
            analysis_id=analysis.id
        )
        log_records.append(log)

    db.add_all(log_records)
    db.flush()

    # 5. Rule-based & Custom Threat Detection
    alerts_data = analyze_rules(df, custom_rules=custom_rules)

    created_alerts = []
    for a in alerts_data:
        ml_row = df[(df['source_ip'] == a['source_ip']) & (df['timestamp'] == a['timestamp'])]
        ml_score = float(ml_row['ml_anomaly_score'].iloc[0]) if not ml_row.empty else 0.0
        ml_reason = str(ml_row['ml_anomaly_reason'].iloc[0]) if not ml_row.empty else ""

        # Risk score calculation
        score, level, explanation = calculate_risk(a['severity'], [("Detection Rule Trigger", 10.0)], ml_score=ml_score)

        # Match log entry ID
        matched_log = next((l for l in log_records if l.source_ip == a['source_ip'] and str(l.timestamp)[:19] == str(a['timestamp'])[:19]), None)

        alert = models.Alert(
            timestamp=a['timestamp'],
            source_ip=a['source_ip'],
            destination_ip=a.get('destination_ip'),
            username=a.get('username'),
            event=a['event'],
            threat_type=a['threat_type'],
            severity=a['severity'],
            risk_score=score,
            risk_level=level,
            risk_factors=explanation,
            detection_reason=a['detection_reason'],
            detection_rule=a.get('detection_rule', 'RULE_DEFAULT'),
            ml_anomaly_result=f"ML Anomaly Score: {ml_score:.1f}/100. {ml_reason}".strip(),
            recommended_action=a['recommended_action'],
            mitre_technique=a.get('mitre_technique'),
            status="New",
            original_log_id=matched_log.id if matched_log else None,
            analysis_id=analysis.id
        )
        db.add(alert)
        created_alerts.append(alert)

    # 6. ML Anomaly Alerts for pure statistical outliers
    high_anomalies = df[(df['is_anomaly'] == True) & (df['ml_anomaly_score'] >= 75.0)]
    for _, row in high_anomalies.iterrows():
        exists = any(a.timestamp == row['timestamp'] and a.source_ip == row['source_ip'] for a in created_alerts)
        if not exists:
            score, level, explanation = calculate_risk("HIGH", [("Pure ML Statistical Anomaly", 15.0)], ml_score=float(row['ml_anomaly_score']))
            matched_log = next((l for l in log_records if l.source_ip == row['source_ip'] and l.timestamp == row['timestamp']), None)
            
            alert = models.Alert(
                timestamp=row['timestamp'],
                source_ip=str(row['source_ip']),
                destination_ip=str(row['destination_ip']) if pd.notna(row.get('destination_ip')) else None,
                username=str(row['username']),
                event="Abnormal Traffic / Activity Baseline Outlier",
                threat_type="Statistical Anomaly",
                severity="HIGH",
                risk_score=score,
                risk_level=level,
                risk_factors=explanation,
                detection_reason=row.get('ml_anomaly_reason') or "Unusual multidimensional feature pattern identified by Isolation Forest.",
                detection_rule="ML_ISOLATION_FOREST_ANOMALY",
                ml_anomaly_result=f"Anomaly Score: {row['ml_anomaly_score']:.1f}/100. Event type: {row['event_type']}",
                recommended_action="Audit origin entity for unusual remote network traffic or anomalous activity.",
                mitre_technique="T1078.004",
                status="New",
                original_log_id=matched_log.id if matched_log else None,
                analysis_id=analysis.id
            )
            db.add(alert)
            created_alerts.append(alert)

    db.commit()

    # 7. Correlate Incidents
    created_incidents = correlate_incidents(created_alerts, db, analysis_id=analysis.id)

    # 8. Update AnalysisSession Summary
    crit_count = len([a for a in created_alerts if a.severity == "CRITICAL"])
    max_risk = max([a.risk_score for a in created_alerts], default=0.0)
    analysis.threat_count = len(created_alerts)
    analysis.critical_count = crit_count
    analysis.risk_score = max_risk
    analysis.status = "Completed"
    db.commit()

    return {
        "message": "Logs successfully ingested and analyzed.",
        "analysis_id": analysis.id,
        "logs_count": len(df),
        "threats_count": len(created_alerts),
        "critical_count": crit_count,
        "incidents_count": len(created_incidents),
        "overall_risk_score": max_risk
    }

@router.get("/search")
def search_logs(
    db: Session = Depends(get_db),
    q: Optional[str] = Query(None, description="Global text search"),
    severity: Optional[str] = Query(None, description="Severity filter (CRITICAL, HIGH, MEDIUM, LOW, INFO)"),
    source_ip: Optional[str] = Query(None, description="Source IP filter"),
    username: Optional[str] = Query(None, description="Username filter"),
    event_type: Optional[str] = Query(None, description="Event type filter"),
    auth_status: Optional[str] = Query(None, description="Authentication status filter"),
    status_code: Optional[int] = Query(None, description="HTTP status code filter"),
    analysis_id: Optional[int] = Query(None, description="Analysis session ID"),
    sort_by: Optional[str] = Query("timestamp", description="Column to sort by"),
    sort_order: Optional[str] = Query("desc", description="Sort order: asc or desc"),
    page: int = Query(1, ge=1, description="Page number"),
    page_size: int = Query(50, ge=1, le=500, description="Items per page")
):
    """
    High-performance, server-side multi-parameter search and filter for Log Explorer.
    """
    query = db.query(models.LogEntry)

    # Filters
    if q:
        search_pattern = f"%{q}%"
        query = query.filter(
            or_(
                models.LogEntry.message.ilike(search_pattern),
                models.LogEntry.source_ip.ilike(search_pattern),
                models.LogEntry.username.ilike(search_pattern),
                models.LogEntry.raw_log.ilike(search_pattern),
                models.LogEntry.url_path.ilike(search_pattern)
            )
        )

    if severity and severity.upper() != "ALL":
        query = query.filter(models.LogEntry.severity == severity.upper())

    if source_ip:
        query = query.filter(models.LogEntry.source_ip == source_ip)

    if username:
        query = query.filter(models.LogEntry.username == username)

    if event_type and event_type.upper() != "ALL":
        query = query.filter(models.LogEntry.event_type.ilike(f"%{event_type}%"))

    if auth_status and auth_status.upper() != "ALL":
        query = query.filter(models.LogEntry.auth_status == auth_status.upper())

    if status_code:
        query = query.filter(models.LogEntry.status_code == status_code)

    if analysis_id:
        query = query.filter(models.LogEntry.analysis_id == analysis_id)

    total = query.count()

    # Sorting
    sort_col = getattr(models.LogEntry, sort_by, models.LogEntry.timestamp)
    if sort_order.lower() == "asc":
        query = query.order_by(asc(sort_col))
    else:
        query = query.order_by(desc(sort_col))

    # Pagination
    offset = (page - 1) * page_size
    items = query.offset(offset).limit(page_size).all()
    total_pages = (total + page_size - 1) // page_size if total > 0 else 1

    return {
        "items": items,
        "total": total,
        "page": page,
        "page_size": page_size,
        "total_pages": total_pages
    }

@router.get("/{log_id}")
def get_log_details(log_id: int, db: Session = Depends(get_db)):
    """
    Fetches detailed view of a single log entry, including any linked alert,
    incident context, and related events.
    """
    log = db.query(models.LogEntry).filter(models.LogEntry.id == log_id).first()
    if not log:
        raise HTTPException(status_code=404, detail="Log entry not found.")

    alert = db.query(models.Alert).filter(models.Alert.original_log_id == log_id).first()
    related_events = (
        db.query(models.LogEntry)
        .filter(models.LogEntry.source_ip == log.source_ip, models.LogEntry.id != log_id)
        .order_by(desc(models.LogEntry.timestamp))
        .limit(5)
        .all()
    )

    return {
        "log": log,
        "alert": alert,
        "related_events": related_events,
        "why_suspicious": alert.detection_reason if alert else ("Non-standard severity" if log.severity in ["HIGH", "CRITICAL"] else "Normal operational baseline."),
        "recommended_action": alert.recommended_action if alert else "No defensive action required for standard baseline log."
    }

@router.get("", include_in_schema=False)
@router.get("/")
def get_logs(db: Session = Depends(get_db), limit: int = 100, skip: int = 0):
    logs = db.query(models.LogEntry).order_by(models.LogEntry.timestamp.desc()).offset(skip).limit(limit).all()
    return logs

