import re
import json
import pandas as pd
from datetime import datetime
from io import StringIO

# Compiled regex patterns for performance
IP_RE = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
WEB_LOG_RE = re.compile(r'^(\S+)\s+\S+\s+(\S+)\s+\[([^\]]+)\]\s+"([A-Z]+)\s+([^"\s]+)(?:\s+([^"]+))?"\s+(\d{3})\s+(\S+)(?:\s+"([^"]*)"\s+"([^"]*)")?')
LINUX_AUTH_RE = re.compile(r'^([A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+([^:\[]+)(?:\[\d+\])?:\s+(.*)$')
WINDOWS_EVENT_RE = re.compile(r'(?:Event\s+(\d{4})|(\d{4})),\s*(.*)', re.IGNORECASE)
KV_RE = re.compile(r'([a-zA-Z0-9_\-\.]+)=(?:"([^"]*)"|\'([^\']*)\'|(\S+))')
PREFIX_RE = re.compile(r'^(?:\[?(\d{4}[-/.]\d{2}[-/.]\d{2}[T\s]\d{2}:\d{2}:\d{2}(?:\.\d+)?)\]?\s+)?(?:([A-Z]{3,8})\s+)?(?:([A-Z0-9_\-]+)\s+)?', re.IGNORECASE)
ISO_TS_RE = re.compile(r'^\[?(\d{4}[-/.]\d{2}[-/.]\d{2}[T\s]\d{2}:\d{2}:\d{2}(?:\.\d+)?)\]?')

SEVERITY_MAP = {
    'CRIT': 'CRITICAL', 'CRITICAL': 'CRITICAL', 'FATAL': 'CRITICAL',
    'HIGH': 'HIGH', 'ERROR': 'HIGH', 'ERR': 'HIGH',
    'WARN': 'MEDIUM', 'WARNING': 'MEDIUM', 'MEDIUM': 'MEDIUM',
    'INFO': 'INFO', 'NOTICE': 'INFO', 'LOW': 'LOW',
    'DEBUG': 'LOW', 'TRACE': 'LOW'
}

def parse_log_file(content: str, filename: str = "") -> pd.DataFrame:
    """
    Parses a log file (JSON, CSV, or unstructured plain text) into a pandas DataFrame.
    Returns a DataFrame with standardized columns:
    timestamp, source_ip, destination_ip, username, hostname, event_type,
    http_method, url_path, status_code, port, protocol, auth_status,
    severity, message, raw_log, user_agent
    """
    content = content.strip()
    if not content:
        return pd.DataFrame()
        
    # 1. JSON detection (file extension or JSON array / object format)
    if filename.endswith(".json") or (content.startswith("[") and content.endswith("]")) or (content.startswith("{") and "\n" not in content):
        df = parse_json_log(content)
        if not df.empty:
            return df

    # 2. CSV detection: check extension or explicit CSV header
    lines = [l for l in content.splitlines() if l.strip()]
    if lines:
        first_line = lines[0].lower()
        has_csv_header = any(k in first_line for k in ["timestamp,", "source_ip,", "src_ip,", "event_type,", "username,"])
        if filename.endswith(".csv") or has_csv_header:
            df = parse_csv(content)
            if not df.empty:
                return df
            
    # 3. Line-by-line multi-format parser (Linux auth, Windows, Web, Firewall, Generic)
    return parse_unstructured_logs(content)

def parse_json_log(content: str) -> pd.DataFrame:
    try:
        if content.startswith("["):
            data = json.loads(content)
        else:
            # JSON Lines format
            data = [json.loads(line) for line in content.splitlines() if line.strip()]
            
        records = []
        for item in data:
            if not isinstance(item, dict):
                continue
            rec = {
                "timestamp": pd.to_datetime(item.get("timestamp") or item.get("time") or datetime.utcnow(), errors="coerce"),
                "source_ip": item.get("source_ip") or item.get("src_ip") or item.get("ip") or "Unknown",
                "destination_ip": item.get("destination_ip") or item.get("dst_ip") or None,
                "username": item.get("username") or item.get("user") or "Unknown",
                "hostname": item.get("hostname") or item.get("host") or None,
                "event_type": item.get("event_type") or item.get("event") or item.get("action") or "Unknown",
                "http_method": item.get("http_method") or item.get("method") or None,
                "url_path": item.get("url_path") or item.get("url") or item.get("path") or None,
                "status_code": int(item.get("status_code") or item.get("status")) if str(item.get("status_code") or item.get("status") or "").isdigit() else None,
                "port": int(item.get("port") or item.get("src_port") or item.get("dst_port")) if str(item.get("port") or "").isdigit() else None,
                "protocol": item.get("protocol") or item.get("proto") or None,
                "auth_status": item.get("auth_status") or None,
                "severity": (item.get("severity") or item.get("level") or "INFO").upper(),
                "message": item.get("message") or item.get("msg") or "",
                "user_agent": item.get("user_agent") or item.get("agent") or None,
                "raw_log": json.dumps(item)
            }
            records.append(rec)
        df = pd.DataFrame(records)
        return standardize_df(df)
    except Exception as e:
        print(f"JSON parse error: {e}")
        return pd.DataFrame()

def parse_csv(content: str) -> pd.DataFrame:
    try:
        df = pd.read_csv(StringIO(content))
        # Standardize column names
        rename_map = {}
        for col in df.columns:
            c = str(col).lower().strip().replace(" ", "_")
            if c in ["time", "datetime", "date"]: rename_map[col] = "timestamp"
            elif c in ["src", "src_ip", "client_ip", "ip"]: rename_map[col] = "source_ip"
            elif c in ["dst", "dst_ip", "dest_ip", "target_ip"]: rename_map[col] = "destination_ip"
            elif c in ["user", "account", "login_user"]: rename_map[col] = "username"
            elif c in ["host", "computer_name"]: rename_map[col] = "hostname"
            elif c in ["event", "action", "type", "activity"]: rename_map[col] = "event_type"
            elif c in ["method"]: rename_map[col] = "http_method"
            elif c in ["uri", "path", "url"]: rename_map[col] = "url_path"
            elif c in ["status_code", "http_status", "response_code"]: rename_map[col] = "status_code"
            elif c in ["status", "code"]:
                # Check if values are numeric (e.g. 200, 404) or textual (e.g. SUCCESS, FAILED, ACTIVE)
                sample_vals = [str(x).strip() for x in df[col].dropna().head(10)]
                if sample_vals and all(x.isdigit() for x in sample_vals):
                    rename_map[col] = "status_code"
                else:
                    rename_map[col] = "auth_status"
            elif c in ["auth_status", "login_status", "result"]: rename_map[col] = "auth_status"
            elif c in ["level"]: rename_map[col] = "severity"
            elif c in ["msg", "details", "description"]: rename_map[col] = "message"
            elif c in ["agent"]: rename_map[col] = "user_agent"
            elif c in ["proto"]: rename_map[col] = "protocol"
        df = df.rename(columns=rename_map)
        
        if "raw_log" not in df.columns:
            df["raw_log"] = [','.join(map(str, row)) for row in df.values]
            
        return standardize_df(df)
    except Exception as e:
        print(f"CSV parse error: {e}")
        return pd.DataFrame()

def parse_unstructured_logs(content: str) -> pd.DataFrame:
    records = []
    lines = content.strip().split("\n")
    current_year = datetime.utcnow().year

    for line in lines:
        line_clean = line.strip()
        if not line_clean:
            continue

        entry = {
            "timestamp": datetime.utcnow(),
            "source_ip": "Unknown",
            "destination_ip": None,
            "username": "Unknown",
            "hostname": None,
            "event_type": "system_event",
            "http_method": None,
            "url_path": None,
            "status_code": None,
            "port": None,
            "protocol": None,
            "auth_status": None,
            "severity": "INFO",
            "message": line_clean,
            "user_agent": None,
            "raw_log": line_clean
        }

        # 1. Check Web Server Access Log (Apache / Nginx Combined or Common format)
        web_match = WEB_LOG_RE.match(line_clean)
        if web_match:
            ip, user, ts_str, method, url, proto, status, size, referer, agent = web_match.groups()
            entry["source_ip"] = ip
            if user != "-": entry["username"] = user
            entry["http_method"] = method
            entry["url_path"] = url
            entry["protocol"] = proto
            entry["status_code"] = int(status) if status.isdigit() else None
            entry["user_agent"] = agent if agent and agent != "-" else None
            entry["event_type"] = "web_request"
            entry["message"] = f"{method} {url} HTTP status {status}"
            try:
                entry["timestamp"] = datetime.strptime(ts_str.split()[0], "%d/%b/%Y:%H:%M:%S")
            except:
                pass
            if int(status) >= 500:
                entry["severity"] = "HIGH"
            elif int(status) in [401, 403]:
                entry["severity"] = "MEDIUM"
                entry["auth_status"] = "FAILED"
            records.append(entry)
            continue

        # 2. Check Linux Syslog / Auth Log
        linux_match = LINUX_AUTH_RE.match(line_clean)
        if linux_match:
            ts_str, host, proc, msg = linux_match.groups()
            entry["hostname"] = host
            entry["message"] = msg
            try:
                dt = datetime.strptime(f"{current_year} {ts_str}", "%Y %b %d %H:%M:%S")
                entry["timestamp"] = dt
            except:
                pass

            # SSH failed password
            fail_m = re.search(r'Failed password for (?:invalid user )?(\S+) from (\S+) port (\d+)', msg)
            if fail_m:
                entry["username"] = fail_m.group(1)
                entry["source_ip"] = fail_m.group(2)
                entry["port"] = int(fail_m.group(3))
                entry["event_type"] = "failed_login"
                entry["auth_status"] = "FAILED"
                entry["severity"] = "WARNING"
                records.append(entry)
                continue

            # SSH accepted
            acc_m = re.search(r'Accepted (?:password|publickey) for (\S+) from (\S+) port (\d+)', msg)
            if acc_m:
                entry["username"] = acc_m.group(1)
                entry["source_ip"] = acc_m.group(2)
                entry["port"] = int(acc_m.group(3))
                entry["event_type"] = "successful_login"
                entry["auth_status"] = "SUCCESS"
                entry["severity"] = "INFO"
                records.append(entry)
                continue

            # Sudo command
            sudo_m = re.search(r'sudo:\s+(\S+)\s*:.*COMMAND=(.*)', line_clean)
            if sudo_m:
                entry["username"] = sudo_m.group(1)
                entry["event_type"] = "privilege_escalation"
                entry["severity"] = "HIGH"
                entry["message"] = f"sudo execution: {sudo_m.group(2)}"
                records.append(entry)
                continue

        # 3. Check Windows Security Event Log
        win_m = WINDOWS_EVENT_RE.search(line_clean)
        if win_m:
            event_id = win_m.group(1) or win_m.group(2)
            rem = win_m.group(3)
            ips = IP_RE.findall(line_clean)
            if ips: entry["source_ip"] = ips[0]
            
            user_m = re.search(r'Account Name:\s*([^\s,;]+)', rem, re.IGNORECASE)
            if user_m: entry["username"] = user_m.group(1)

            if event_id == "4624":
                entry["event_type"] = "successful_login"
                entry["auth_status"] = "SUCCESS"
                entry["severity"] = "INFO"
            elif event_id == "4625":
                entry["event_type"] = "failed_login"
                entry["auth_status"] = "FAILED"
                entry["severity"] = "WARNING"
            elif event_id == "4672":
                entry["event_type"] = "privilege_escalation"
                entry["severity"] = "HIGH"
            elif event_id == "4740":
                entry["event_type"] = "account_lockout"
                entry["severity"] = "HIGH"
            elif event_id == "4720":
                entry["event_type"] = "user_creation"
                entry["severity"] = "MEDIUM"
                
            records.append(entry)
            continue

        # 4. Check Structured Key-Value Log (e.g. Syslog KV, Splunk, CEF, AWS, or modern SOC security logs)
        if "=" in line_clean and (
            any(k in line_clean.lower() for k in ["src_ip=", "source_ip=", "user=", "action=", "method=", "path=", "status=", "host=", "dst_ip="])
            or " " in line_clean
        ):
            kvs = {}
            for m in KV_RE.finditer(line_clean):
                k = m.group(1).lower()
                val = m.group(2) if m.group(2) is not None else (m.group(3) if m.group(3) is not None else m.group(4))
                kvs[k] = val

            if len(kvs) >= 2 or any(k in kvs for k in ["src_ip", "source_ip", "ip", "user", "username", "action", "host"]):
                m_pref = PREFIX_RE.match(line_clean)
                ts_val = None
                sev_val = "INFO"
                category_val = ""

                if m_pref:
                    ts_str = m_pref.group(1)
                    if ts_str:
                        try:
                            ts_val = pd.to_datetime(ts_str)
                        except Exception:
                            pass
                    s_cand = (m_pref.group(2) or "").upper()
                    if s_cand in SEVERITY_MAP:
                        sev_val = SEVERITY_MAP[s_cand]
                    category_val = (m_pref.group(3) or "").upper()

                ips = IP_RE.findall(line_clean)
                src_ip = kvs.get("src_ip") or kvs.get("source_ip") or kvs.get("ip") or (ips[0] if ips else "Unknown")
                dst_ip = kvs.get("dst_ip") or kvs.get("destination_ip") or (ips[1] if len(ips) > 1 and ips[1] != src_ip else None)

                user = kvs.get("user") or kvs.get("username") or kvs.get("account") or "Unknown"
                host = kvs.get("host") or kvs.get("hostname")
                method = kvs.get("method") or kvs.get("http_method")
                path = kvs.get("path") or kvs.get("url") or kvs.get("url_path")
                status_raw = kvs.get("status") or kvs.get("status_code") or ""
                action = kvs.get("action", "").lower()

                status_code = int(status_raw) if status_raw.isdigit() else None
                port_raw = kvs.get("port") or kvs.get("dst_port") or kvs.get("src_port")
                port = int(port_raw) if port_raw and str(port_raw).isdigit() else None

                auth_status = None
                if status_raw.lower() in ["success", "succeeded", "ok", "pass"]:
                    auth_status = "SUCCESS"
                elif status_raw.lower() in ["failed", "failure", "fail", "invalid"]:
                    auth_status = "FAILED"
                elif action in ["account_locked", "locked"]:
                    auth_status = "FAILED"

                # Event type determination
                if action in ["sudo", "role_change"] or category_val == "PRIVILEGE":
                    event_type = "privilege_escalation"
                elif action in ["account_locked", "lockout"]:
                    event_type = "account_lockout"
                elif category_val == "MALWARE" or action in ["detected", "quarantined"] or "malware" in line_clean.lower():
                    event_type = "malware_detected"
                elif action == "login":
                    event_type = "failed_login" if auth_status == "FAILED" else "successful_login"
                elif action == "logout":
                    event_type = "user_logout"
                elif method or category_val == "HTTP":
                    event_type = "web_request"
                elif (category_val in ["FIREWALL", "NETWORK"] or status_raw.lower() == "blocked") and status_raw.lower() == "blocked":
                    event_type = "firewall_block"
                elif category_val in ["FIREWALL", "NETWORK"]:
                    event_type = "network_connection"
                elif action:
                    event_type = action
                elif category_val:
                    event_type = f"{category_val.lower()}_event"
                else:
                    event_type = "system_event"

                msg = kvs.get("message") or kvs.get("msg")
                if not msg:
                    if kvs.get("command"):
                        msg = f"{action}: {kvs['command']}"
                    elif path:
                        msg = f"{method or 'HTTP'} {path} status={status_raw}"
                    elif kvs.get("process"):
                        msg = f"Process {kvs['process']} on {host or 'host'} action={action} status={status_raw}"
                    else:
                        msg = line_clean

                entry["timestamp"] = ts_val or datetime.utcnow()
                entry["source_ip"] = src_ip
                entry["destination_ip"] = dst_ip
                entry["username"] = user
                entry["hostname"] = host
                entry["event_type"] = event_type
                entry["http_method"] = method
                entry["url_path"] = path
                entry["status_code"] = status_code
                entry["port"] = port
                entry["protocol"] = kvs.get("proto") or kvs.get("protocol")
                entry["auth_status"] = auth_status
                entry["severity"] = sev_val
                entry["message"] = msg
                entry["raw_log"] = line_clean

                records.append(entry)
                continue

        # 5. Check Firewall Key-Value Log (e.g. iptables, pfSense, Cisco)
        if "SRC=" in line_clean and "DST=" in line_clean:
            src_m = re.search(r'SRC=([^\s]+)', line_clean)
            dst_m = re.search(r'DST=([^\s]+)', line_clean)
            proto_m = re.search(r'PROTO=([^\s]+)', line_clean)
            spt_m = re.search(r'SPT=(\d+)', line_clean)
            dpt_m = re.search(r'DPT=(\d+)', line_clean)
            if src_m: entry["source_ip"] = src_m.group(1)
            if dst_m: entry["destination_ip"] = dst_m.group(1)
            if proto_m: entry["protocol"] = proto_m.group(1)
            if dpt_m: entry["port"] = int(dpt_m.group(1))
            
            if "BLOCK" in line_clean or "DENY" in line_clean or "DROP" in line_clean:
                entry["event_type"] = "firewall_block"
                entry["severity"] = "MEDIUM"
            else:
                entry["event_type"] = "firewall_traffic"
                entry["severity"] = "INFO"
            records.append(entry)
            continue

        # 6. Generic / Unknown Fallback
        ts_m = ISO_TS_RE.match(line_clean)
        if ts_m:
            try:
                entry["timestamp"] = pd.to_datetime(ts_m.group(1))
            except Exception:
                pass

        ips = IP_RE.findall(line_clean)
        if ips:
            entry["source_ip"] = ips[0]
            if len(ips) > 1:
                entry["destination_ip"] = ips[1]
                
        # Username heuristics
        usr_m = re.search(r'(?:user|username|account)[:=]\s*([^\s,;]+)', line_clean, re.IGNORECASE)
        if usr_m:
            entry["username"] = usr_m.group(1)

        # Severity heuristics
        for sev in ["CRITICAL", "HIGH", "WARN", "WARNING", "ERROR", "INFO", "DEBUG"]:
            if re.search(rf'\b{sev}\b', line_clean, re.IGNORECASE):
                entry["severity"] = "HIGH" if sev in ["ERROR", "WARN", "WARNING"] else ("CRITICAL" if sev == "CRITICAL" else ("LOW" if sev == "DEBUG" else "INFO"))
                break

        # Event heuristics
        lower_line = line_clean.lower()
        if "fail" in lower_line and "login" in lower_line:
            entry["event_type"] = "failed_login"
            entry["auth_status"] = "FAILED"
        elif "success" in lower_line and "login" in lower_line:
            entry["event_type"] = "successful_login"
            entry["auth_status"] = "SUCCESS"
        elif "lockout" in lower_line or re.search(r'\blocked\b', lower_line):
            entry["event_type"] = "account_lockout"
            
        records.append(entry)

    df = pd.DataFrame(records)
    return standardize_df(df)

def standardize_df(df: pd.DataFrame) -> pd.DataFrame:
    """Ensures all standard columns are present, typed, and not null."""
    if df.empty:
        return df
    expected_cols = [
        "timestamp", "source_ip", "destination_ip", "username", "hostname",
        "event_type", "http_method", "url_path", "status_code", "port",
        "protocol", "auth_status", "severity", "message", "raw_log", "user_agent"
    ]
    for col in expected_cols:
        if col not in df.columns:
            df[col] = None
            
    df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce").fillna(datetime.utcnow())
    df["source_ip"] = df["source_ip"].fillna("Unknown")
    df["username"] = df["username"].fillna("Unknown")
    df["event_type"] = df["event_type"].fillna("system_event")
    df["severity"] = df["severity"].fillna("INFO").astype(str).str.upper()
    df["message"] = df["message"].fillna("")
    df["raw_log"] = df["raw_log"].fillna(df["message"])
    
    # Safe numeric conversion
    df["status_code"] = pd.to_numeric(df["status_code"], errors="coerce")
    df["port"] = pd.to_numeric(df["port"], errors="coerce")
    
    # Extract port from message if port is missing
    missing_ports = df["port"].isna()
    if missing_ports.any():
        extracted = df.loc[missing_ports, "message"].astype(str).str.extract(r'(?:port|DPT|SPT)[:=\s]+(\d+)', flags=re.IGNORECASE)[0]
        df.loc[missing_ports, "port"] = pd.to_numeric(extracted, errors="coerce")

    return df

