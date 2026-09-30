from sqlalchemy import create_engine, text, inspect
from sqlalchemy.orm import declarative_base
from sqlalchemy.orm import sessionmaker
import os

# Support DATABASE_URL from environment with fallback to local SQLite
DATABASE_URL = os.environ.get("DATABASE_URL")

if DATABASE_URL:
    # Fix legacy postgres:// URL scheme from Heroku/Render if present
    if DATABASE_URL.startswith("postgres://"):
        DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)
    
    if DATABASE_URL.startswith("sqlite"):
        engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
    else:
        # PostgreSQL / MySQL cloud engine
        engine = create_engine(DATABASE_URL, pool_pre_ping=True)
else:
    # Default local SQLite file
    DB_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), "analyzer.db")
    SQLALCHEMY_DATABASE_URL = f"sqlite:///{DB_PATH}"
    engine = create_engine(
        SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False}
    )

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()

def run_auto_migrations():
    """Ensures existing tables are non-destructively migrated with any missing columns."""
    try:
        inspector = inspect(engine)
        existing_tables = inspector.get_table_names()
    except Exception as e:
        print(f"Inspection note: {e}")
        return

    with engine.connect() as conn:
        # Check logs columns
        if "logs" in existing_tables:
            existing_log_cols = [c["name"] for c in inspector.get_columns("logs")]
            new_log_cols = {
                "destination_ip": "TEXT",
                "hostname": "TEXT",
                "http_method": "TEXT",
                "url_path": "TEXT",
                "status_code": "INTEGER",
                "port": "INTEGER",
                "protocol": "TEXT",
                "auth_status": "TEXT",
                "user_agent": "TEXT",
                "analysis_id": "INTEGER"
            }
            for col, col_type in new_log_cols.items():
                if col not in existing_log_cols and existing_log_cols:
                    try:
                        conn.execute(text(f"ALTER TABLE logs ADD COLUMN {col} {col_type}"))
                        conn.commit()
                    except Exception as e:
                        print(f"Migration note for logs.{col}: {e}")

        # Check alerts columns
        if "alerts" in existing_tables:
            existing_alert_cols = [c["name"] for c in inspector.get_columns("alerts")]
            new_alert_cols = {
                "destination_ip": "TEXT",
                "risk_level": "TEXT",
                "risk_factors": "TEXT",
                "detection_rule": "TEXT",
                "incident_id": "INTEGER",
                "analysis_id": "INTEGER"
            }
            for col, col_type in new_alert_cols.items():
                if col not in existing_alert_cols and existing_alert_cols:
                    try:
                        conn.execute(text(f"ALTER TABLE alerts ADD COLUMN {col} {col_type}"))
                        conn.commit()
                    except Exception as e:
                        print(f"Migration note for alerts.{col}: {e}")
        
        # Create indexes for fast querying and performance
        indexes = [
            "CREATE INDEX IF NOT EXISTS idx_logs_timestamp ON logs(timestamp);",
            "CREATE INDEX IF NOT EXISTS idx_logs_source_ip ON logs(source_ip);",
            "CREATE INDEX IF NOT EXISTS idx_logs_event_type ON logs(event_type);",
            "CREATE INDEX IF NOT EXISTS idx_logs_severity ON logs(severity);",
            "CREATE INDEX IF NOT EXISTS idx_logs_analysis_id ON logs(analysis_id);",
            "CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON alerts(timestamp);",
            "CREATE INDEX IF NOT EXISTS idx_alerts_source_ip ON alerts(source_ip);",
            "CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity);",
            "CREATE INDEX IF NOT EXISTS idx_alerts_threat_type ON alerts(threat_type);",
            "CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts(status);"
        ]
        for idx in indexes:
            try:
                conn.execute(text(idx))
                conn.commit()
            except Exception:
                pass

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


