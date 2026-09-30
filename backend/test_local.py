import unittest
from fastapi.testclient import TestClient
from app.main import app
from app.database import database, models

class TestSocPlatformLocal(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(app)
        # Ensure database tables exist
        models.Base.metadata.create_all(bind=database.engine)

    def test_01_health_check(self):
        response = self.client.get("/api/health")
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data.get("status"), "ok")

    def test_02_sample_logs_ingestion(self):
        response = self.client.post("/api/logs/sample")
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertIn("analysis_id", data)
        self.assertGreater(data.get("logs_count", 0), 0)
        self.assertGreater(data.get("threats_count", 0), 0)
        self.__class__.analysis_id = data.get("analysis_id")

    def test_03_paste_logs_ingestion(self):
        log_payload = {
            "content": """2026-09-23 10:00:00,10.0.0.99,attacker,failed_login,WARNING,Failed password for invalid user admin
2026-09-23 10:00:05,10.0.0.99,attacker,failed_login,WARNING,Failed password for invalid user admin
2026-09-23 10:00:10,10.0.0.99,attacker,failed_login,WARNING,Failed password for invalid user admin
2026-09-23 10:00:15,10.0.0.99,attacker,failed_login,WARNING,Failed password for invalid user admin
2026-09-23 10:00:20,10.0.0.99,attacker,failed_login,WARNING,Failed password for invalid user admin
2026-09-23 10:00:25,10.0.0.99,attacker,successful_login,INFO,Accepted password for attacker""",
            "filename": "test_bruteforce.log"
        }
        response = self.client.post("/api/logs/paste", json=log_payload)
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertGreaterEqual(data.get("logs_count", 0), 6)

    def test_04_dashboard_stats(self):
        response = self.client.get("/api/dashboard/")
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertIn("summary", data)
        self.assertIn("charts", data)
        self.assertGreater(data["summary"]["total_logs"], 0)
        self.assertIn("events_over_time", data["charts"])

    def test_05_dashboard_auth_analytics(self):
        response = self.client.get("/api/dashboard/auth-analytics")
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertIn("total_attempts", data)
        self.assertIn("failed_logins", data)
        self.assertIn("successful_logins", data)

    def test_06_logs_search(self):
        response = self.client.get("/api/logs/search?page=1&page_size=10")
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertIn("items", data)
        self.assertIn("total", data)
        self.assertGreater(data["total"], 0)

        # Test single log detail
        first_id = data["items"][0]["id"]
        detail_resp = self.client.get(f"/api/logs/{first_id}")
        self.assertEqual(detail_resp.status_code, 200)
        self.assertIn("log", detail_resp.json())

    def test_07_alerts_and_status(self):
        response = self.client.get("/api/alerts/")
        self.assertEqual(response.status_code, 200)
        alerts = response.json()
        self.assertIsInstance(alerts, list)
        if len(alerts) > 0:
            first_alert = alerts[0]
            alert_id = first_alert["id"]
            
            # Single alert inspection
            single_resp = self.client.get(f"/api/alerts/{alert_id}")
            self.assertEqual(single_resp.status_code, 200)
            
            # Update status
            upd_resp = self.client.put(f"/api/alerts/{alert_id}/status", json={"status": "Investigating"})
            self.assertEqual(upd_resp.status_code, 200)
            self.assertEqual(upd_resp.json().get("status"), "Investigating")

    def test_08_incidents_and_status(self):
        response = self.client.get("/api/incidents/")
        self.assertEqual(response.status_code, 200)
        incidents = response.json()
        self.assertIsInstance(incidents, list)
        if len(incidents) > 0:
            first_inc = incidents[0]
            inc_id = first_inc["id"]

            # Single incident detail
            single_resp = self.client.get(f"/api/incidents/{inc_id}")
            self.assertEqual(single_resp.status_code, 200)
            self.assertIn("timeline", single_resp.json())

            # Test updating status (standard and case-insensitive/mapped)
            upd_resp1 = self.client.put(f"/api/incidents/{inc_id}/status", json={"status": "Investigating"})
            self.assertEqual(upd_resp1.status_code, 200)
            
            upd_resp2 = self.client.put(f"/api/incidents/{inc_id}/status", json={"status": "OPEN"})
            self.assertEqual(upd_resp2.status_code, 200)
            self.assertEqual(upd_resp2.json().get("status"), "New")

    def test_09_ip_analysis_endpoints(self):
        response = self.client.get("/api/ips/")
        self.assertEqual(response.status_code, 200)
        ips = response.json()
        self.assertIsInstance(ips, list)
        if len(ips) > 0:
            first_ip = ips[0]
            self.assertIn("ip", first_ip)
            self.assertIn("request_count", first_ip)
            self.assertIn("total_events", first_ip)
            self.assertEqual(first_ip["request_count"], first_ip["total_events"])

            # Single IP Profile
            profile_resp = self.client.get(f"/api/ips/{first_ip['ip']}")
            self.assertEqual(profile_resp.status_code, 200)
            prof_data = profile_resp.json()
            self.assertIn("associated_alerts", prof_data)
            self.assertIn("associated_logs", prof_data)
            self.assertIn("target_users", prof_data)

    def test_10_custom_rules_crud(self):
        rule_payload = {
            "name": "Local Test Sudo Detector",
            "description": "Flags unauthorized sudo invocations",
            "field": "message",
            "operator": "contains",
            "pattern": "sudo:",
            "severity": "HIGH",
            "threat_type": "Privilege Escalation"
        }
        # Create
        create_resp = self.client.post("/api/rules/", json=rule_payload)
        self.assertEqual(create_resp.status_code, 200)
        rule_data = create_resp.json()
        self.assertEqual(rule_data.get("field_name"), "message")
        self.assertEqual(rule_data.get("field"), "message")
        rule_id = rule_data.get("id")

        # Toggle
        toggle_resp = self.client.patch(f"/api/rules/{rule_id}/toggle")
        self.assertEqual(toggle_resp.status_code, 200)

        # Delete
        del_resp = self.client.delete(f"/api/rules/{rule_id}")
        self.assertEqual(del_resp.status_code, 200)

    def test_11_reports_summary_and_export(self):
        # Summary
        summary_resp = self.client.get("/api/reports/summary")
        self.assertEqual(summary_resp.status_code, 200)
        summary = summary_resp.json()
        self.assertIn("metrics", summary)
        self.assertIn("top_suspicious_ips", summary)
        self.assertIn("critical_incidents", summary)
        self.assertIn("recommended_actions", summary)

        # JSON Export - MUST NOT throw serialization error
        export_json_resp = self.client.get("/api/reports/export?format=json")
        self.assertEqual(export_json_resp.status_code, 200)
        self.assertIn("application/json", export_json_resp.headers.get("content-type", ""))

        # CSV Export
        export_csv_resp = self.client.get("/api/reports/export?format=csv")
        self.assertEqual(export_csv_resp.status_code, 200)
        self.assertIn("text/csv", export_csv_resp.headers.get("content-type", ""))

    def test_12_copilot_ai(self):
        # AI Summary
        summary_resp = self.client.get("/api/copilot/ai-summary")
        self.assertEqual(summary_resp.status_code, 200)
        ai_data = summary_resp.json()
        self.assertIn("executive_summary", ai_data)
        self.assertIn("recommended_actions", ai_data)

        # Chat query
        chat_resp = self.client.post("/api/copilot/chat", json={"question": "What happened?"})
        self.assertEqual(chat_resp.status_code, 200)
        chat_data = chat_resp.json()
        self.assertIn("answer", chat_data)

    def test_13_history_endpoints(self):
        response = self.client.get("/api/history/")
        self.assertEqual(response.status_code, 200)
        sessions = response.json()
        self.assertIsInstance(sessions, list)
        if len(sessions) > 0:
            first_session_id = sessions[0]["id"]
            detail_resp = self.client.get(f"/api/history/{first_session_id}")
            self.assertEqual(detail_resp.status_code, 200)

if __name__ == "__main__":
    unittest.main()
