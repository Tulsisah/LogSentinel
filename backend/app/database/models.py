from sqlalchemy import Column, Integer, String, Float, DateTime, Text, Boolean, ForeignKey
from .database import Base
import datetime

class AnalysisSession(Base):
    __tablename__ = "analyses"

    id = Column(Integer, primary_key=True, index=True)
    filename = Column(String, default="manual_input")
    created_at = Column(DateTime, default=datetime.datetime.utcnow, index=True)
    log_count = Column(Integer, default=0)
    threat_count = Column(Integer, default=0)
    critical_count = Column(Integer, default=0)
    risk_score = Column(Float, default=0.0)
    status = Column(String, default="Completed")

class LogEntry(Base):
    __tablename__ = "logs"

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=datetime.datetime.utcnow, index=True)
    source_ip = Column(String, index=True, default="Unknown")
    destination_ip = Column(String, index=True, nullable=True)
    username = Column(String, index=True, default="Unknown")
    hostname = Column(String, nullable=True)
    event_type = Column(String, index=True, default="Unknown")
    http_method = Column(String, nullable=True)
    url_path = Column(String, nullable=True)
    status_code = Column(Integer, nullable=True)
    port = Column(Integer, nullable=True)
    protocol = Column(String, nullable=True)
    auth_status = Column(String, nullable=True) # SUCCESS, FAILED, N/A
    severity = Column(String, default="INFO", index=True) # INFO, LOW, MEDIUM, HIGH, CRITICAL
    message = Column(Text, default="")
    raw_log = Column(Text, default="")
    user_agent = Column(String, nullable=True)
    analysis_id = Column(Integer, ForeignKey("analyses.id"), nullable=True, index=True)

class Incident(Base):
    __tablename__ = "incidents"

    id = Column(Integer, primary_key=True, index=True)
    title = Column(String, index=True)
    severity = Column(String, index=True) # LOW, MEDIUM, HIGH, CRITICAL
    risk_score = Column(Float, default=0.0)
    risk_level = Column(String, default="Low") # Low, Moderate, Medium, High, Critical
    source_ip = Column(String, index=True)
    target_username = Column(String, nullable=True, index=True)
    attack_type = Column(String, index=True)
    explanation = Column(Text)
    recommended_action = Column(Text)
    status = Column(String, default="New", index=True) # New, Investigating, Resolved, False Positive
    created_at = Column(DateTime, default=datetime.datetime.utcnow, index=True)
    analysis_id = Column(Integer, ForeignKey("analyses.id"), nullable=True, index=True)
    event_count = Column(Integer, default=0)

class Alert(Base):
    __tablename__ = "alerts"

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=datetime.datetime.utcnow, index=True)
    source_ip = Column(String, index=True)
    destination_ip = Column(String, nullable=True)
    username = Column(String, nullable=True, index=True)
    event = Column(String) # The event that triggered this
    threat_type = Column(String, index=True)
    severity = Column(String, index=True) # INFO, LOW, MEDIUM, HIGH, CRITICAL
    risk_score = Column(Float, default=0.0)
    risk_level = Column(String, default="Low") # Low, Moderate, Medium, High, Critical
    risk_factors = Column(Text, nullable=True) # JSON / explanation of factors
    detection_reason = Column(Text)
    detection_rule = Column(String, nullable=True)
    ml_anomaly_result = Column(Text, nullable=True)
    recommended_action = Column(Text)
    status = Column(String, default="New", index=True) # New, Investigating, Resolved, False Positive
    original_log_id = Column(Integer, ForeignKey("logs.id"), nullable=True)
    mitre_technique = Column(String, nullable=True)
    incident_id = Column(Integer, ForeignKey("incidents.id"), nullable=True, index=True)
    analysis_id = Column(Integer, ForeignKey("analyses.id"), nullable=True, index=True)

class CustomRule(Base):
    __tablename__ = "custom_rules"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, unique=True, index=True)
    description = Column(String)
    field_name = Column(String, default="message") # event_type, message, source_ip, username, status_code
    operator = Column(String, default="contains") # contains, equals, regex, greater_than
    pattern = Column(String)
    threshold = Column(Integer, default=1)
    window_minutes = Column(Integer, default=5)
    same_ip = Column(Boolean, default=True)
    severity = Column(String, default="HIGH")
    threat_type = Column(String, default="Custom Threat")
    mitre_technique = Column(String, default="T1059")
    recommended_action = Column(Text, default="Review correlated events and isolate endpoint.")
    enabled = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    hashed_password = Column(String)
    role = Column(String, default="Analyst") # Admin, Analyst
    created_at = Column(DateTime, default=datetime.datetime.utcnow)

