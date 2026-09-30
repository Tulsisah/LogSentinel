import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import LabelEncoder
import numpy as np
from datetime import datetime

def run_anomaly_detection(df: pd.DataFrame) -> pd.DataFrame:
    """
    Applies Isolation Forest to detect anomalous logs and calculates
    interpretable reasons explaining WHY each anomaly was flagged.
    Adds 'ml_anomaly_score', 'is_anomaly', and 'ml_anomaly_reason' to the dataframe.
    """
    if df.empty:
        return df

    # Default fallback columns
    df['ml_anomaly_score'] = 0.0
    df['is_anomaly'] = False
    df['ml_anomaly_reason'] = ""

    if len(df) < 5:
        return df

    # Feature Engineering
    features = pd.DataFrame()
    df['timestamp'] = pd.to_datetime(df['timestamp'], errors='coerce').fillna(datetime.utcnow())
    features['hour'] = df['timestamp'].dt.hour

    le_ip = LabelEncoder()
    le_user = LabelEncoder()
    le_event = LabelEncoder()

    features['ip_encoded'] = le_ip.fit_transform(df['source_ip'].astype(str))
    features['user_encoded'] = le_user.fit_transform(df['username'].astype(str))
    features['event_encoded'] = le_event.fit_transform(df['event_type'].astype(str))
    features['msg_length'] = df['message'].fillna("").apply(len)

    # Statistical baselines for explainability
    total_events = len(df)
    event_freqs = df['event_type'].value_counts(normalize=True)
    mean_msg_len = features['msg_length'].mean()
    std_msg_len = features['msg_length'].std() if features['msg_length'].std() > 0 else 1.0

    # Request frequency per IP
    ip_counts = df['source_ip'].value_counts()
    avg_ip_count = ip_counts.mean()

    # Train Isolation Forest
    contamination = 0.05 if total_events >= 20 else 0.1
    clf = IsolationForest(n_estimators=100, contamination=contamination, random_state=42)
    predictions = clf.fit_predict(features)
    raw_scores = clf.decision_function(features)

    # Invert and normalize to 0-100 scale
    inverted = -raw_scores
    min_val = np.min(inverted)
    max_val = np.max(inverted)
    if max_val > min_val:
        normalized = ((inverted - min_val) / (max_val - min_val)) * 100
    else:
        normalized = np.zeros(len(inverted))

    df['ml_anomaly_score'] = normalized
    df['is_anomaly'] = (predictions == -1) | (normalized >= 75.0)

    # Generate explainable reasons for anomalous events
    reasons = []
    for idx, row in df.iterrows():
        if not row['is_anomaly'] and row['ml_anomaly_score'] < 70.0:
            reasons.append("")
            continue

        detected_reasons = []
        hour = row['timestamp'].hour
        if hour < 5 or hour >= 23:
            detected_reasons.append(f"Abnormal login/event hour ({hour:02d}:00 UTC) outside typical business baseline")

        ev_type = row['event_type']
        freq = event_freqs.get(ev_type, 0.0) * 100
        if freq <= 5.0:
            detected_reasons.append(f"Rare event type '{ev_type}' (occurs in {freq:.1f}% of traffic)")

        msg_len = len(str(row.get('message', '')))
        if msg_len > mean_msg_len + (2 * std_msg_len) and msg_len > 80:
            detected_reasons.append(f"Unusual payload length ({msg_len} chars vs baseline avg {int(mean_msg_len)})")

        ip = row['source_ip']
        if ip != "Unknown" and ip_counts.get(ip, 0) > avg_ip_count * 2.5:
            detected_reasons.append(f"Unusual request frequency spike from IP {ip} ({ip_counts.get(ip)} events)")

        if not detected_reasons:
            detected_reasons.append(f"Multi-dimensional deviation detected by Isolation Forest (anomaly score: {row['ml_anomaly_score']:.1f}/100)")

        reasons.append("; ".join(detected_reasons))

    df['ml_anomaly_reason'] = reasons
    return df

