import re
import pandas as pd
from typing import List, Dict, Tuple, Optional
from datetime import datetime

# Threat Detection Constants
BRUTE_FORCE_THRESHOLD = 5
BRUTE_FORCE_WINDOW_MINUTES = 5
PORT_SCAN_THRESHOLD = 4

# Attack Signatures
SQLI_RE = re.compile(r"('|\%27)\s*(OR|AND)\s*('|\%27)?\d+('|\%27)?\s*=\s*('|\%27)?\d+|UNION\s+SELECT|SLEEP\s*\(|INFORMATION_SCHEMA|xp_cmdshell|WAITFOR\s+DELAY", re.IGNORECASE)
XSS_RE = re.compile(r"<script.*?>|javascript:|onerror\s*=|onload\s*=|alert\(|<img.*?src=", re.IGNORECASE)
TRAVERSAL_RE = re.compile(r"(\.\./|\.\.\\|%2e%2e%2f|%2e%2e/|/etc/passwd|win\.ini|/windows/system32)", re.IGNORECASE)
CMD_INJ_RE = re.compile(r"(?:;|\||`|\$\()\s*(?:whoami|cat\s+/|rm\s+-|net\s+user|powershell|wget|curl|nc\s+|bash\s+-i)", re.IGNORECASE)
ENCODED_PAYLOAD_RE = re.compile(r"-(?:enc|encodedcommand)\s+[A-Za-z0-9+/=]{20,}", re.IGNORECASE)
PERSISTENCE_RE = re.compile(r"(?:schtasks\s+/create|crontab\s+-e|CurrentVersion\\Run|sc\s+create|systemctl\s+enable)", re.IGNORECASE)
SUSPICIOUS_TOOLS_RE = re.compile(r"(?:mimikatz|certutil.*-urlcache|vssadmin\s+delete|psexec|ncat\s+-e|/bin/sh\s+-i)", re.IGNORECASE)

def calculate_risk(base_severity: str, factor_weights: List[Tuple[str, float]], ml_score: float = 0.0) -> Tuple[float, str, str]:
    """
    Calculates a standardized 0-100 risk score, risk level, and explanation.
    Tiers:
      0–20: Low
      21–40: Moderate
      41–60: Medium
      61–80: High
      81–100: Critical
    """
    severity_bases = {
        "CRITICAL": 85.0,
        "HIGH": 70.0,
        "MEDIUM": 45.0,
        "LOW": 20.0,
        "INFO": 10.0
    }
    score = severity_bases.get(base_severity.upper(), 50.0)
    
    explanation_parts = [f"Base severity: {base_severity} ({int(score)} pts)"]
    
    # Add factor modifiers
    for reason, weight in factor_weights:
        score += weight
        explanation_parts.append(f"{reason} (+{int(weight)} pts)")
        
    # Incorporate ML anomaly score (weighted)
    if ml_score > 60.0:
        ml_bonus = (ml_score - 60.0) * 0.25
        score += ml_bonus
        explanation_parts.append(f"ML anomaly indicator ({ml_score:.1f}/100, +{int(ml_bonus)} pts)")
        
    score = min(max(score, 0.0), 100.0)
    
    # Classify tier
    if score >= 81.0:
        level = "Critical"
    elif score >= 61.0:
        level = "High"
    elif score >= 41.0:
        level = "Medium"
    elif score >= 21.0:
        level = "Moderate"
    else:
        level = "Low"
        
    explanation = f"Score {score:.0f}/100 ({level}) derived from: " + "; ".join(explanation_parts) + "."
    return score, level, explanation

def analyze_rules(df: pd.DataFrame, custom_rules: Optional[List[Dict]] = None) -> List[Dict]:
    """
    Applies comprehensive security detection rules and custom rules on the log dataframe.
    Returns a list of structured alert dictionaries.
    """
    alerts = []
    if df.empty:
        return alerts

    df = df.sort_values(by='timestamp').copy()
    
    # 1. Brute Force & Account Compromise
    failed_mask = (
        (df['event_type'].isin(['failed_login', 'Failed Login', 'login_failed'])) |
        (df['auth_status'] == 'FAILED') |
        (df['event_type'].str.contains('LOGIN', case=False, na=False) & (df.get('status_code', 0) == 401)) |
        (df.get('message', '').str.contains('Failed password|Failed SSH login|Invalid password|4625', case=False, na=False))
    )
    failed_logins = df[failed_mask]

    for ip, group in failed_logins.groupby('source_ip'):
        if ip in [None, "Unknown", ""]:
            continue
        if len(group) >= BRUTE_FORCE_THRESHOLD:
            # Check rolling window
            group_indexed = group.set_index('timestamp')
            counts = group_indexed.rolling(f'{BRUTE_FORCE_WINDOW_MINUTES}min').count()
            brute_force_events = counts[counts['event_type'] >= BRUTE_FORCE_THRESHOLD]
            
            if not brute_force_events.empty:
                first_bf_time = brute_force_events.index[0]
                count_val = int(brute_force_events['event_type'].iloc[0])
                target_user = group['username'].iloc[0] if not group.empty else "Unknown"
                
                factors = [("Repeated authentication failures in short window", 15.0)]
                score, level, explanation = calculate_risk("HIGH", factors)
                
                alerts.append({
                    "timestamp": first_bf_time,
                    "source_ip": ip,
                    "username": target_user,
                    "event": "Multiple Failed Logins (Brute Force)",
                    "threat_type": "Brute Force",
                    "severity": "HIGH",
                    "risk_score": score,
                    "risk_level": level,
                    "risk_factors": explanation,
                    "detection_reason": f"{count_val} failed authentication attempts observed from IP {ip} within {BRUTE_FORCE_WINDOW_MINUTES} minutes.",
                    "detection_rule": "AUTH_BRUTE_FORCE_ROLLING",
                    "recommended_action": "Temporarily block the source IP on perimeter firewalls and inspect targeted account activity.",
                    "mitre_technique": "T1110"
                })
                
                # Check for Successful Login Immediately After (Account Compromise)
                success_mask = (df['source_ip'] == ip) & (df['timestamp'] >= first_bf_time) & (
                    df['event_type'].isin(['successful_login', 'Successful Login', 'login_success']) |
                    (df['auth_status'] == 'SUCCESS') |
                    (df.get('message', '').str.contains('Accepted (?:password|publickey)|logged on|4624', case=False, na=False))
                )
                subsequent_success = df[success_mask]
                if not subsequent_success.empty:
                    succ_time = subsequent_success.iloc[0]['timestamp']
                    succ_user = subsequent_success.iloc[0]['username']
                    
                    comp_factors = [
                        ("Authentication success following brute force burst", 15.0),
                        ("High probability of credential breach", 10.0)
                    ]
                    comp_score, comp_level, comp_exp = calculate_risk("CRITICAL", comp_factors)
                    
                    alerts.append({
                        "timestamp": succ_time,
                        "source_ip": ip,
                        "username": succ_user,
                        "event": "Successful Login After Repeated Failures",
                        "threat_type": "Account Compromise",
                        "severity": "CRITICAL",
                        "risk_score": comp_score,
                        "risk_level": comp_level,
                        "risk_factors": comp_exp,
                        "detection_reason": f"A successful login for account '{succ_user}' occurred immediately after brute-force attempts from IP {ip}.",
                        "detection_rule": "AUTH_COMPROMISE_POST_BRUTEFORCE",
                        "recommended_action": "Immediately revoke active user sessions, reset account credentials, and isolate endpoint.",
                        "mitre_technique": "T1078"
                    })

    # 2. Port Scanning Detection
    port_scan_ips = set()
    if 'port' in df.columns:
        for ip, group in df.groupby('source_ip'):
            if ip in [None, "Unknown", ""] or len(group) < PORT_SCAN_THRESHOLD:
                continue
            unique_ports = group['port'].dropna().unique()
            if len(unique_ports) >= PORT_SCAN_THRESHOLD:
                port_scan_ips.add(ip)
                scan_factors = [("Probing multiple distinct network ports", 10.0)]
                scan_score, scan_level, scan_exp = calculate_risk("HIGH", scan_factors)
                alerts.append({
                    "timestamp": group['timestamp'].iloc[0],
                    "source_ip": ip,
                    "username": group['username'].iloc[0] if not group.empty else "Unknown",
                    "event": "Network Port Scanning Activity",
                    "threat_type": "Reconnaissance",
                    "severity": "HIGH",
                    "risk_score": scan_score,
                    "risk_level": scan_level,
                    "risk_factors": scan_exp,
                    "detection_reason": f"Source IP {ip} probed {len(unique_ports)} distinct ports within session: {list(unique_ports)[:6]}.",
                    "detection_rule": "NET_PORT_SCAN_DISCOVERY",
                    "recommended_action": "Inspect edge firewall ingress logs and restrict scanning IP on perimeter ACLs.",
                    "mitre_technique": "T1046"
                })

    # Also check PORT_SCAN event types or messages if not already alerted
    port_mask = (df['event_type'].astype(str).str.upper().isin(['PORT_SCAN', 'PORT_SCANNING'])) | (df['message'].astype(str).str.contains('connection probe|port scan', case=False, na=False))
    for ip, group in df[port_mask].groupby('source_ip'):
        if ip not in port_scan_ips and len(group) >= 3:
            port_scan_ips.add(ip)
            scan_factors = [("Port scan probes detected in network telemetry", 10.0)]
            scan_score, scan_level, scan_exp = calculate_risk("HIGH", scan_factors)
            alerts.append({
                "timestamp": group['timestamp'].iloc[0],
                "source_ip": ip,
                "username": group['username'].iloc[0] if not group.empty else "Unknown",
                "event": "Network Port Scanning Activity",
                "threat_type": "Reconnaissance",
                "severity": "HIGH",
                "risk_score": scan_score,
                "risk_level": scan_level,
                "risk_factors": scan_exp,
                "detection_reason": f"Source IP {ip} generated {len(group)} port scanning probes against target assets.",
                "detection_rule": "NET_PORT_SCAN_DISCOVERY",
                "recommended_action": "Block source IP on border firewall and review exposed service listeners.",
                "mitre_technique": "T1046"
            })

    # 3. Account Lockout Detection
    lockout_mask = (df['event_type'].astype(str).str.upper().isin(['ACCOUNT_LOCKOUT', 'LOCKED_OUT', 'ACCOUNT_LOCKED'])) | (df['message'].astype(str).str.contains('account locked|Event 4740|locked out', case=False, na=False))
    for _, row in df[lockout_mask].iterrows():
        l_factors = [("Security lockout policy triggered", 10.0)]
        l_score, l_level, l_exp = calculate_risk("HIGH", l_factors)
        alerts.append({
            "timestamp": row['timestamp'],
            "source_ip": row['source_ip'],
            "username": row['username'],
            "event": "User Account Locked Out",
            "threat_type": "Account Lockout",
            "severity": "HIGH",
            "risk_score": l_score,
            "risk_level": l_level,
            "risk_factors": l_exp,
            "detection_reason": f"Account '{row['username']}' locked out due to exceeding maximum authentication threshold.",
            "detection_rule": "AUTH_ACCOUNT_LOCKOUT",
            "recommended_action": "Contact user to verify authentication attempts and review recent source IPs.",
            "mitre_technique": "T1110.001"
        })

    # 4. Privilege Escalation Detection
    priv_mask = (df['event_type'].astype(str).str.upper().isin(['PRIVILEGE_ESCALATION', 'PRIVILEGE_ESCALATION_ATTEMPT'])) | (df['message'].astype(str).str.contains('sudo:|Event 4672|whoami /priv|setuid|Special privileges assigned|Unauthorized attempt to obtain elevated privileges', case=False, na=False))
    for _, row in df[priv_mask].iterrows():
        p_factors = [("Elevated system privilege transition requested", 15.0)]
        p_score, p_level, p_exp = calculate_risk("CRITICAL", p_factors)
        alerts.append({
            "timestamp": row['timestamp'],
            "source_ip": row['source_ip'],
            "username": row['username'],
            "event": "Privilege Escalation Activity",
            "threat_type": "Privilege Escalation",
            "severity": "CRITICAL",
            "risk_score": p_score,
            "risk_level": p_level,
            "risk_factors": p_exp,
            "detection_reason": f"Privileged command or special authorization detected for user '{row['username']}': {row['message']}",
            "detection_rule": "SEC_PRIVILEGE_ESCALATION",
            "recommended_action": "Audit sudoers / Administrator assignments and verify if escalation was authorized.",
            "mitre_technique": "T1548"
        })

    # 5. Suspicious HTTP Activity (SQLi, XSS, Path Traversal, Command Injection)
    for idx, row in df.iterrows():
        test_str = f"{row.get('url_path', '')} {row.get('message', '')}"
        
        # SQL Injection
        if SQLI_RE.search(test_str):
            factors = [("Injected SQL syntax keywords in request parameters", 15.0)]
            score, level, exp = calculate_risk("HIGH", factors)
            alerts.append({
                "timestamp": row['timestamp'],
                "source_ip": row['source_ip'],
                "username": row['username'],
                "event": "SQL Injection Attempt Detected",
                "threat_type": "Web Application Attack",
                "severity": "HIGH",
                "risk_score": score,
                "risk_level": level,
                "risk_factors": exp,
                "detection_reason": f"SQL syntax manipulation pattern observed: {test_str[:120]}...",
                "detection_rule": "WEB_SQL_INJECTION",
                "recommended_action": "Verify database query parameterization and update WAF rules to block signature.",
                "mitre_technique": "T1190"
            })
            continue

        # XSS
        if XSS_RE.search(test_str):
            factors = [("Cross-Site Scripting HTML tag/handler detected", 10.0)]
            score, level, exp = calculate_risk("HIGH", factors)
            alerts.append({
                "timestamp": row['timestamp'],
                "source_ip": row['source_ip'],
                "username": row['username'],
                "event": "Cross-Site Scripting (XSS) Indicator",
                "threat_type": "Web Application Attack",
                "severity": "HIGH",
                "risk_score": score,
                "risk_level": level,
                "risk_factors": exp,
                "detection_reason": f"Unsanitized script payload detected in HTTP request: {test_str[:120]}...",
                "detection_rule": "WEB_CROSS_SITE_SCRIPTING",
                "recommended_action": "Implement strict output encoding and Content-Security-Policy (CSP) headers.",
                "mitre_technique": "T1059.007"
            })
            continue

        # Path Traversal
        if TRAVERSAL_RE.search(test_str):
            factors = [("Path directory traversal dot-dot-slash sequence", 15.0)]
            score, level, exp = calculate_risk("HIGH", factors)
            alerts.append({
                "timestamp": row['timestamp'],
                "source_ip": row['source_ip'],
                "username": row['username'],
                "event": "Directory Traversal Attempt",
                "threat_type": "Web Application Attack",
                "severity": "HIGH",
                "risk_score": score,
                "risk_level": level,
                "risk_factors": exp,
                "detection_reason": f"Attempt to access parent directory or sensitive system file: {test_str[:120]}...",
                "detection_rule": "WEB_PATH_TRAVERSAL",
                "recommended_action": "Sanitize user path inputs and restrict web daemon permissions to root doc directory.",
                "mitre_technique": "T1083"
            })
            continue

        # Command Injection
        if (CMD_INJ_RE.search(test_str) or re.search(r'suspicious command|command input detected', test_str, re.IGNORECASE)) and row['event_type'] != 'failed_login':
            factors = [("OS shell chaining character or command execution", 20.0)]
            score, level, exp = calculate_risk("CRITICAL", factors)
            alerts.append({
                "timestamp": row['timestamp'],
                "source_ip": row['source_ip'],
                "username": row['username'],
                "event": "OS Command Injection Indicator",
                "threat_type": "Command Injection",
                "severity": "CRITICAL",
                "risk_score": score,
                "risk_level": level,
                "risk_factors": exp,
                "detection_reason": f"Shell command execution sequence detected in payload: {test_str[:120]}...",
                "detection_rule": "SYS_COMMAND_INJECTION",
                "recommended_action": "Immediately check server process tree, terminate unauthorized sub-shells, and isolate host.",
                "mitre_technique": "T1059"
            })
            continue

        # Web Probing & Reconnaissance
        if str(row.get('event_type', '')).upper() == 'WEB_PROBE' or re.search(r'(?:/(?:admin|wp-admin|\.env|backup\.zip|config\.php|phpmyadmin|server-status|api/debug))', test_str, re.IGNORECASE):
            factors = [("Sensitive path enumeration and administrative probing", 10.0)]
            score, level, exp = calculate_risk("MEDIUM", factors)
            alerts.append({
                "timestamp": row['timestamp'],
                "source_ip": row['source_ip'],
                "username": row['username'],
                "event": "Web Reconnaissance & Sensitive Resource Probe",
                "threat_type": "Reconnaissance",
                "severity": "MEDIUM",
                "risk_score": score,
                "risk_level": level,
                "risk_factors": exp,
                "detection_reason": f"Probing attempt directed at sensitive endpoints: {test_str[:120]}...",
                "detection_rule": "WEB_SENSITIVE_RESOURCE_PROBE",
                "recommended_action": "Inspect access frequency and apply rate-limiting or ACL blocks on source IP.",
                "mitre_technique": "T1595.002"
            })
            continue

        # Encoded Payloads & Suspicious Process / PowerShell
        ev_proc = str(row.get('event_type', '')).upper()
        msg_proc = str(row.get('message', '')).lower()
        if ev_proc == 'SUSPICIOUS_PROCESS' or 'powershell' in msg_proc or 'unusual command interpreter' in msg_proc or ENCODED_PAYLOAD_RE.search(test_str):
            is_crit = "encoded" in msg_proc or "credential" in msg_proc or bool(ENCODED_PAYLOAD_RE.search(test_str))
            sev = "CRITICAL" if is_crit else "HIGH"
            factors = [("Anomalous shell / script interpreter execution", 15.0)]
            score, level, exp = calculate_risk(sev, factors)
            alerts.append({
                "timestamp": row['timestamp'],
                "source_ip": row['source_ip'],
                "username": row['username'],
                "event": "Suspicious Process / Encoded PowerShell Execution",
                "threat_type": "Command and Scripting Interpreter",
                "severity": sev,
                "risk_score": score,
                "risk_level": level,
                "risk_factors": exp,
                "detection_reason": f"Suspicious interpreter activity observed for user '{row['username']}': {row['message']}",
                "detection_rule": "SYS_SUSPICIOUS_PROCESS_EXECUTION",
                "recommended_action": "Isolate affected endpoint, verify parent process genealogy, and collect memory artifacts.",
                "mitre_technique": "T1059.001"
            })
            continue

        # Persistence Indicators
        if PERSISTENCE_RE.search(test_str):
            factors = [("Persistence mechanism setup detected", 15.0)]
            score, level, exp = calculate_risk("HIGH", factors)
            alerts.append({
                "timestamp": row['timestamp'],
                "source_ip": row['source_ip'],
                "username": row['username'],
                "event": "Persistence Mechanism Installed",
                "threat_type": "Persistence",
                "severity": "HIGH",
                "risk_score": score,
                "risk_level": level,
                "risk_factors": exp,
                "detection_reason": f"Creation of scheduled task, service, or autorun entry: {test_str[:120]}...",
                "detection_rule": "SYS_PERSISTENCE_CREATION",
                "recommended_action": "Inspect Windows Task Scheduler or crontab, inspect persistence keys, and remove malicious entries.",
                "mitre_technique": "T1053"
            })
            continue

        # Suspicious Tools (mimikatz, certutil, reverse shell)
        if SUSPICIOUS_TOOLS_RE.search(test_str):
            factors = [("Known offensive tool or credential dumper signature", 25.0)]
            score, level, exp = calculate_risk("CRITICAL", factors)
            alerts.append({
                "timestamp": row['timestamp'],
                "source_ip": row['source_ip'],
                "username": row['username'],
                "event": "Offensive Security Tool / Dropper Detected",
                "threat_type": "Malware / Defense Evasion",
                "severity": "CRITICAL",
                "risk_score": score,
                "risk_level": level,
                "risk_factors": exp,
                "detection_reason": f"High-confidence threat signature detected: {test_str[:120]}...",
                "detection_rule": "MALWARE_OFFENSIVE_TOOL",
                "recommended_action": "Perform immediate endpoint isolation and memory dump collection.",
                "mitre_technique": "T1003"
            })
            continue

    # 6. Data Transfer / Exfiltration
    for idx, row in df.iterrows():
        ev_exfil = str(row.get('event_type', '')).upper()
        msg_exfil = str(row.get('message', '')).lower()
        if ev_exfil in ['DATA_TRANSFER', 'FILE_DOWNLOAD', 'LARGE DATA TRANSFER', 'UNUSUAL_OUTBOUND'] or 'unusual outbound' in msg_exfil or 'exfiltration' in msg_exfil:
            factors = [("High-volume data egress to external network host", 15.0)]
            score, level, exp = calculate_risk("HIGH", factors)
            alerts.append({
                "timestamp": row['timestamp'],
                "source_ip": row['source_ip'],
                "username": row['username'],
                "event": "Unusual Outbound Data Exfiltration Activity",
                "threat_type": "Exfiltration",
                "severity": "HIGH",
                "risk_score": score,
                "risk_level": level,
                "risk_factors": exp,
                "detection_reason": f"Anomalous egress data transfer to remote destination: {row['message']}",
                "detection_rule": "EXFILTRATION_DATA_TRANSFER",
                "recommended_action": "Review egress network flows, block destination external IP on perimeter firewall, and initiate DLP triage.",
                "mitre_technique": "T1048"
            })

    # 7. Endpoint Malware / Quarantined Threat Detection
    malware_mask = (
        (df['event_type'].astype(str).str.lower().isin(['malware_detected', 'malware', 'threat_detected'])) |
        (df['message'].astype(str).str.contains('malware|quarantine|ransomware|trojan|miner|cryptominer', case=False, na=False))
    )
    for _, row in df[malware_mask].iterrows():
        m_factors = [("Endpoint antimalware detection alert", 20.0)]
        m_score, m_level, m_exp = calculate_risk("CRITICAL", m_factors)
        alerts.append({
            "timestamp": row['timestamp'],
            "source_ip": row['source_ip'],
            "destination_ip": row.get('destination_ip'),
            "username": row['username'],
            "event": "Malicious Process / Malware Activity Detected",
            "threat_type": "Malware Detection",
            "severity": "CRITICAL",
            "risk_score": m_score,
            "risk_level": m_level,
            "risk_factors": m_exp,
            "detection_reason": f"Endpoint host '{row.get('hostname') or 'workstation'}' detected malware: {row['message']}",
            "detection_rule": "EP_MALWARE_DETECTED",
            "recommended_action": "Isolate the infected endpoint immediately, run memory acquisition, and review execution logs.",
            "mitre_technique": "T1204"
        })

    # 8. Evaluate Custom Detection Rules (from Database)
    if custom_rules:
        for rule in custom_rules:
            if not rule.get('enabled', True):
                continue
            field = rule.get('field_name', 'message')
            operator = rule.get('operator', 'contains')
            pattern = rule.get('pattern', '')
            threshold = rule.get('threshold', 1)
            
            matching_rows = []
            for _, row in df.iterrows():
                val = str(row.get(field, ''))
                matched = False
                if operator == 'contains' and pattern.lower() in val.lower():
                    matched = True
                elif operator == 'equals' and pattern.lower() == val.lower():
                    matched = True
                elif operator == 'regex':
                    try:
                        if re.search(pattern, val, re.IGNORECASE):
                            matched = True
                    except:
                        pass
                elif operator == 'greater_than':
                    try:
                        if float(val) > float(pattern):
                            matched = True
                    except:
                        pass
                if matched:
                    matching_rows.append(row)
                    
            if len(matching_rows) >= threshold:
                first_row = matching_rows[0]
                sev = rule.get('severity', 'HIGH').upper()
                c_factors = [("User-defined custom detection rule matched", 10.0)]
                c_score, c_level, c_exp = calculate_risk(sev, c_factors)
                alerts.append({
                    "timestamp": first_row['timestamp'],
                    "source_ip": first_row['source_ip'],
                    "username": first_row['username'],
                    "event": f"Custom Rule Trigger: {rule.get('name')}",
                    "threat_type": rule.get('threat_type', 'Custom Threat'),
                    "severity": sev,
                    "risk_score": c_score,
                    "risk_level": c_level,
                    "risk_factors": c_exp,
                    "detection_reason": f"Triggered by custom rule '{rule.get('name')}': {rule.get('description', '')} (Matched {len(matching_rows)} events).",
                    "detection_rule": f"CUSTOM_{rule.get('name').replace(' ', '_').upper()}",
                    "recommended_action": rule.get('recommended_action', 'Investigate correlated events according to organization SOP.'),
                    "mitre_technique": rule.get('mitre_technique', 'T1059')
                })

    return alerts

