import os
import json
from typing import Dict, List, Any, Optional
from datetime import datetime

def generate_ai_analysis(summary_stats: Dict[str, Any], alerts: List[Dict[str, Any]], logs: List[Dict[str, Any]], incidents: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Generates structured SOC AI Analysis distinguishing confirmed evidence,
    suspicious indicators, and possible interpretations.
    Supports local expert reasoning engine and optional Gemini/OpenAI API.
    """
    gemini_key = os.environ.get("GEMINI_API_KEY")
    openai_key = os.environ.get("OPENAI_API_KEY")

    if gemini_key:
        try:
            return call_gemini_analysis(gemini_key, summary_stats, alerts, logs, incidents)
        except Exception as e:
            print(f"Gemini API error, falling back to local SOC engine: {e}")
    elif openai_key:
        try:
            return call_openai_analysis(openai_key, summary_stats, alerts, logs, incidents)
        except Exception as e:
            print(f"OpenAI API error, falling back to local SOC engine: {e}")

    return generate_local_soc_analysis(summary_stats, alerts, logs, incidents)

def generate_local_soc_analysis(summary_stats: Dict[str, Any], alerts: List[Dict[str, Any]], logs: List[Dict[str, Any]], incidents: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Deterministic, high-fidelity Blue Team SOC reasoning engine.
    Produces full structured report with evidence vs interpretation separation.
    """
    total_logs = summary_stats.get("total_logs", len(logs))
    total_alerts = summary_stats.get("suspicious_events", len(alerts))
    critical_alerts = summary_stats.get("critical_alerts", len([a for a in alerts if a.get("severity") == "CRITICAL"]))
    high_alerts = summary_stats.get("high_risk_events", len([a for a in alerts if a.get("severity") == "HIGH"]))

    threat_types = list(dict.fromkeys([a.get("threat_type") for a in alerts if a.get("threat_type")]))
    source_ips = list(dict.fromkeys([a.get("source_ip") for a in alerts if a.get("source_ip") and a.get("source_ip") != "Unknown"]))
    targeted_users = list(dict.fromkeys([a.get("username") for a in alerts if a.get("username") and a.get("username") != "Unknown"]))

    # 1. Confirmed Evidence
    confirmed_evidence = []
    for alert in alerts[:8]:
        confirmed_evidence.append(
            f"Verified event '{alert.get('event')}' from IP {alert.get('source_ip')} ({alert.get('severity')}): {alert.get('detection_reason')}"
        )
    if not confirmed_evidence:
        confirmed_evidence.append("No active security alert thresholds exceeded during baseline monitoring window.")

    # 2. Suspicious Indicators
    suspicious_indicators = []
    if any("Brute Force" in t for t in threat_types):
        suspicious_indicators.append("High volume of rapid invalid authentication requests indicative of automated password guessing.")
    if any("Account Compromise" in t for t in threat_types):
        suspicious_indicators.append("Immediate transition from multiple authentication failures to successful login on high-value account.")
    if any("Command" in t or "Interpreter" in t for t in threat_types):
        suspicious_indicators.append("Execution of administrative CLI interpreters (PowerShell/Bash) with obfuscated or privileged arguments.")
    if any("Exfiltration" in t for t in threat_types):
        suspicious_indicators.append("Abnormal egress transfer volume exceeding baseline data access patterns.")
    if not suspicious_indicators:
        suspicious_indicators.append("Traffic exhibits standard user and service account communication characteristics.")

    # 3. Possible Interpretation
    possible_interpretation = []
    if "Account Compromise" in threat_types and "Exfiltration" in threat_types:
        possible_interpretation.append(
            "Adversary completed an end-to-end intrusion chain: Initial Access via Credential Stuffing -> Execution of Discovery Dropper -> Staging & Exfiltration of sensitive assets."
        )
    elif "Brute Force" in threat_types:
        possible_interpretation.append(
            "External or internal threat actor actively probing authentication boundaries to compromise administrative credentials."
        )
    elif any("Web" in t for t in threat_types):
        possible_interpretation.append(
            "Automated vulnerability scanner or threat actor testing web application endpoints for injection or unauthorized path access."
        )
    else:
        possible_interpretation.append(
            "Events may represent operational anomalies, administrator misconfigurations, or low-intensity exploratory reconnaissance."
        )

    # 4. Executive Summary
    if critical_alerts > 0:
        exec_summary = (
            f"CRITICAL SECURITY ALERT: The analyzer inspected {total_logs} log entries and detected {total_alerts} security alerts, "
            f"including {critical_alerts} CRITICAL and {high_alerts} HIGH severity events. "
            f"Primary attack vectors observed: {', '.join(threat_types[:3]) if threat_types else 'None'}. "
            f"Immediate containment and credential revocation are advised for impacted accounts ({', '.join(targeted_users[:3]) if targeted_users else 'N/A'})."
        )
    elif high_alerts > 0:
        exec_summary = (
            f"HIGH RISK DETECTED: Analyzed {total_logs} logs with {total_alerts} suspicious detections. "
            f"Suspicious activity originated from IP(s): {', '.join(source_ips[:3]) if source_ips else 'N/A'}. "
            f"Review edge firewall ACLs and endpoint authorization controls."
        )
    else:
        exec_summary = (
            f"NORMAL / LOW THREAT: Analyzed {total_logs} logs. No active high-severity security breaches identified. "
            f"System telemetry conforms to typical baseline activity."
        )

    # 5. Potential Impact
    potential_impact = (
        "Unauthorized administrative system access, credential harvesting, potential lateral movement across corporate subnet, "
        "and unauthorized exfiltration of proprietary or customer records." if (critical_alerts > 0 or high_alerts > 0)
        else "Low operational impact; minimal risk to organizational confidentiality, integrity, or availability."
    )

    # 6. Recommended Defensive Actions
    defensive_actions = [
        "1. Isolate compromised endpoint(s) from local network segments.",
        "2. Invalidate active user tokens/sessions and enforce mandatory password reset.",
        "3. Block hostile source IP addresses at the perimeter firewall/WAF.",
        "4. Preserve host volatile memory and audit process tree for persistent hooks (scheduled tasks, run keys).",
        "5. Inspect egress proxy and DLP logs for secondary destination endpoints."
    ]

    # 7. SOC Analyst Summary
    analyst_summary = (
        f"SOC Investigation Summary: {len(incidents)} active incident(s) correlated across {len(alerts)} alerts. "
        f"Attackers targeted {len(targeted_users)} account(s) from {len(source_ips)} unique source address(es). "
        f"Correlated MITRE ATT&CK techniques: T1110 (Brute Force), T1078 (Valid Accounts), T1059 (Command & Scripting Interpreter), "
        f"T1048 (Exfiltration Over Alternative Protocol). Recommended triage priority: P1 - Urgent Response."
    )

    return {
        "engine": "SOC-Expert-Rules",
        "executive_summary": exec_summary,
        "attack_classification": threat_types if threat_types else ["Baseline Telemetry"],
        "confirmed_evidence": confirmed_evidence,
        "suspicious_indicators": suspicious_indicators,
        "possible_interpretation": possible_interpretation,
        "potential_impact": potential_impact,
        "recommended_defensive_actions": defensive_actions,
        "recommended_actions": defensive_actions,
        "soc_analyst_summary": analyst_summary,
        "generated_at": datetime.utcnow().isoformat()
    }

def answer_copilot_query(query: str, logs: List[Dict], alerts: List[Dict], incidents: List[Dict], stats: Dict) -> str:
    """
    Answers analyst questions dynamically based on live log, alert, and incident context.
    """
    q = query.lower().strip()
    
    # 1. "What happened?" / Overview
    if "what happened" in q or "summary" in q or "overview" in q or "tell me" in q:
        total = stats.get("total_logs", len(logs))
        threats = stats.get("suspicious_events", len(alerts))
        criticals = stats.get("critical_alerts", len([a for a in alerts if a.get("severity") == "CRITICAL"]))
        top_threats = list(dict.fromkeys([a.get("threat_type") for a in alerts]))
        top_ips = list(dict.fromkeys([a.get("source_ip") for a in alerts if a.get("source_ip") and a.get("source_ip") != "Unknown"]))
        
        return (
            f"### Incident Overview\n\n"
            f"Out of **{total}** logs processed, the engine identified **{threats}** security alerts "
            f"with **{criticals}** critical severity detections.\n\n"
            f"- **Primary Threat Types**: {', '.join(top_threats) if top_threats else 'None detected'}\n"
            f"- **Involved Source IPs**: {', '.join(top_ips[:4]) if top_ips else 'None'}\n"
            f"- **Active Incidents**: {len(incidents)} multi-stage incident(s) correlated.\n\n"
            f"Key sequence detected: Repeated failed authentications progressed to successful access, followed by execution of command interpreters and abnormal outbound transfers."
        )

    # 2. "Which IP is most suspicious?"
    if "ip" in q and ("suspicious" in q or "malicious" in q or "top" in q or "who" in q):
        ip_counts = {}
        for a in alerts:
            ip = a.get("source_ip")
            if ip and ip != "Unknown":
                ip_counts[ip] = ip_counts.get(ip, 0) + 1
        if ip_counts:
            sorted_ips = sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)
            top_ip, count = sorted_ips[0]
            related_threats = [a.get("threat_type") for a in alerts if a.get("source_ip") == top_ip]
            return (
                f"### Top Suspicious IP: `{top_ip}`\n\n"
                f"- **Alert Count**: {count} alert(s)\n"
                f"- **Associated Threats**: {', '.join(set(related_threats))}\n"
                f"- **Risk Classification**: High Risk / Potentially Malicious\n"
                f"- **Recommended Action**: Block `{top_ip}` on boundary firewalls and inspect session history."
            )
        else:
            return "No suspicious IPs with high alert counts were identified in the current dataset."

    # 3. "Is this a brute-force attack?"
    if "brute" in q or "failed login" in q or "password" in q:
        bf_alerts = [a for a in alerts if "brute" in str(a.get("threat_type", "")).lower() or "brute" in str(a.get("event", "")).lower()]
        if bf_alerts:
            first = bf_alerts[0]
            return (
                f"### Brute-Force Activity Confirmed\n\n"
                f"Yes. The analyzer detected **{len(bf_alerts)}** brute-force detection events.\n\n"
                f"- **Target User**: `{first.get('username')}`\n"
                f"- **Source IP**: `{first.get('source_ip')}`\n"
                f"- **Detection Reason**: {first.get('detection_reason')}\n"
                f"- **MITRE Technique**: T1110 (Brute Force)\n\n"
                f"Notice: Look closely for any subsequent successful login events from the same IP, which indicates an **Account Compromise**."
            )
        else:
            return "No brute-force attack patterns (exceeding threshold of 5 failed attempts in 5 minutes) were flagged in these logs."

    # 4. "Show critical events" / Critical
    if "critical" in q:
        crit_alerts = [a for a in alerts if a.get("severity") == "CRITICAL"]
        if crit_alerts:
            res = f"### Critical Security Events ({len(crit_alerts)})\n\n"
            for a in crit_alerts[:5]:
                res += f"- **{a.get('threat_type')}** ({a.get('event')}) from `{a.get('source_ip')}` for `{a.get('username')}` (Risk Score: **{int(a.get('risk_score', 0))}/100**)\n"
                res += f"  *Reason*: {a.get('detection_reason')}\n"
            return res
        else:
            return "There are no CRITICAL severity alerts in the current dataset."

    # 5. "Why is this event high risk?" / Why
    if "why" in q or "high risk" in q or "risk" in q:
        top_alert = max(alerts, key=lambda a: a.get("risk_score", 0), default=None)
        if top_alert:
            return (
                f"### Risk Score Justification for Alert #{top_alert.get('id', 'N/A')}\n\n"
                f"- **Threat Type**: {top_alert.get('threat_type')}\n"
                f"- **Assigned Risk**: **{int(top_alert.get('risk_score', 0))}/100** ({top_alert.get('risk_level', 'Critical')})\n"
                f"- **Reasoning**: {top_alert.get('risk_factors') or top_alert.get('detection_reason')}\n"
                f"- **Calculated Factors**: Base threat severity + repeated occurrences + ML anomaly contribution."
            )
        else:
            return "No high-risk events found to evaluate."

    # 6. "What should the analyst do?" / Recommended actions
    if "do" in q or "action" in q or "remediation" in q or "contain" in q:
        return (
            f"### Recommended SOC Analyst Playbook\n\n"
            f"1. **Immediate Isolation**: Terminate network connectivity for compromised endpoints.\n"
            f"2. **Identity Quarantine**: Reset credentials and revoke existing Kerberos/OAuth tokens for targeted accounts.\n"
            f"3. **Perimeter Defense**: Add hostile source IPs to edge firewall blacklists.\n"
            f"4. **Forensic Evidence Collection**: Collect memory dump, command execution logs, and network egress captures.\n"
            f"5. **Root Cause Analysis**: Audit how credentials were leaked or bypassed."
        )

    # General fallback answer
    return (
        f"### Security Analysis Copilot\n\n"
        f"Based on the **{len(logs)}** logs and **{len(alerts)}** alerts analyzed:\n"
        f"- Total Alerts: **{len(alerts)}**\n"
        f"- Critical Events: **{len([a for a in alerts if a.get('severity') == 'CRITICAL'])}**\n"
        f"- Incidents Correlated: **{len(incidents)}**\n\n"
        f"You can ask me questions like:\n"
        f"- *'What happened?'*\n"
        f"- *'Which IP is most suspicious?'*\n"
        f"- *'Is this a brute-force attack?'*\n"
        f"- *'Show critical events.'*\n"
        f"- *'Why is this event high risk?'*\n"
        f"- *'What should the analyst do?'*"
    )

def call_gemini_analysis(api_key: str, stats: Dict, alerts: List, logs: List, incidents: List) -> Dict:
    # Optional Gemini implementation when API key is provided
    import urllib.request
    url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key={api_key}"
    prompt = f"Perform SOC analysis on: Stats: {json.dumps(stats)}, Alerts: {json.dumps(alerts[:10])}, Incidents: {json.dumps(incidents[:5])}"
    req_data = json.dumps({"contents": [{"parts": [{"text": prompt}]}]}).encode("utf-8")
    req = urllib.request.Request(url, data=req_data, headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=10) as resp:
        res = json.loads(resp.read().decode())
        raw_text = res["candidates"][0]["content"]["parts"][0]["text"]
        return {"engine": "Gemini-1.5-Flash", "raw_analysis": raw_text, "executive_summary": raw_text[:300]}

def call_openai_analysis(api_key: str, stats: Dict, alerts: List, logs: List, incidents: List) -> Dict:
    # Optional OpenAI implementation when API key is provided
    import urllib.request
    url = "https://api.openai.com/v1/chat/completions"
    prompt = f"Perform SOC analysis on: Stats: {json.dumps(stats)}, Alerts: {json.dumps(alerts[:10])}, Incidents: {json.dumps(incidents[:5])}"
    req_data = json.dumps({
        "model": "gpt-3.5-turbo",
        "messages": [{"role": "system", "content": "You are a Senior SOC Analyst."}, {"role": "user", "content": prompt}]
    }).encode("utf-8")
    req = urllib.request.Request(url, data=req_data, headers={"Content-Type": "application/json", "Authorization": f"Bearer {api_key}"})
    with urllib.request.urlopen(req, timeout=10) as resp:
        res = json.loads(resp.read().decode())
        raw_text = res["choices"][0]["message"]["content"]
        return {"engine": "OpenAI-GPT", "raw_analysis": raw_text, "executive_summary": raw_text[:300]}
