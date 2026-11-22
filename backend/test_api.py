"""Focused authorization and authentication regression checks."""
import os
import tempfile
import unittest
from pathlib import Path

from fastapi.testclient import TestClient

from backend import main


def registration_payload(email: str, **overrides) -> dict:
    payload = {
        "full_name": "Sample Customer",
        "email": email,
        "phone": "+1 555 0100",
        "organization": "River Lab",
        "organization_type": "Research institution",
        "country": "Exampleland",
        "state": "North",
        "district": "Delta",
        "city": "Harbor City",
        "region": "East Shore",
        "address": "1 Test Street",
        "password": "correct horse battery",
        "confirm_password": "correct horse battery",
    }
    payload.update(overrides)
    return payload


class QuantLiteSecurityTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.previous_db = main.DATABASE_URL
        self.previous_env = main.APP_ENV
        self.previous_mfa_key = os.environ.get("OWNER_MFA_ENCRYPTION_KEY")
        os.environ["OWNER_MFA_ENCRYPTION_KEY"] = main.Fernet.generate_key().decode("ascii")
        main.DATABASE_URL = f"sqlite:///{Path(self.temp_dir.name) / 'tests.db'}"
        main.APP_ENV = "development"
        self.client = TestClient(main.app)

    def tearDown(self):
        self.client.close()
        main.DATABASE_URL = self.previous_db
        main.APP_ENV = self.previous_env
        if self.previous_mfa_key is None:
            os.environ.pop("OWNER_MFA_ENCRYPTION_KEY", None)
        else:
            os.environ["OWNER_MFA_ENCRYPTION_KEY"] = self.previous_mfa_key
        self.temp_dir.cleanup()

    def register_and_verify(self, email: str) -> str:
        response = self.client.post("/api/auth/register", json=registration_payload(email))
        self.assertEqual(response.status_code, 201, response.text)
        token = response.json()["development_verification_token"]
        verified = self.client.post("/api/auth/verify", json={"token": token})
        self.assertEqual(verified.status_code, 200, verified.text)
        return response.json()["customer_id"]

    def login(self, email: str, portal: str = "CUSTOMER", mfa_code: str | None = None) -> str:
        payload = {"email": email, "password": "correct horse battery", "portal": portal}
        if mfa_code:
            payload["mfa_code"] = mfa_code
        response = self.client.post("/api/auth/login", json=payload)
        self.assertEqual(response.status_code, 200, response.text)
        return response.json()["csrf_token"]

    def create_sample(self, csrf: str) -> str:
        response = self.client.post("/api/customer/tests", headers={"X-CSRF-Token": csrf}, json={
            "sample_type": "Water sample", "country": "Exampleland", "state": "North", "district": "Delta",
            "city": "Harbor City", "region": "East Shore", "latitude": 10.0, "longitude": 20.0,
        })
        self.assertEqual(response.status_code, 201, response.text)
        self.assertEqual(response.json()["test"]["status"], "PENDING")
        self.assertIsNone(response.json()["test"]["detection_json"])
        return response.json()["test"]["id"]

    def test_registration_cannot_assign_admin_role_and_requires_verification(self):
        result = self.client.post("/api/auth/register", json=registration_payload("customer@example.org", role="ADMIN"))
        self.assertEqual(result.status_code, 201, result.text)
        self.assertNotIn("role", result.json())
        blocked = self.client.post("/api/auth/login", json={"email": "customer@example.org", "password": "correct horse battery", "portal": "CUSTOMER"})
        self.assertEqual(blocked.status_code, 403)
        db = main.get_db()
        row = db.execute("SELECT role,email_verified FROM users WHERE email=?", ("customer@example.org",)).fetchone()
        db.close()
        self.assertEqual((row["role"], row["email_verified"]), ("CUSTOMER", 0))

    def test_customer_records_are_owner_scoped_and_admin_routes_reject_customers(self):
        self.register_and_verify("first@example.org")
        csrf = self.login("first@example.org")
        test_id = self.create_sample(csrf)
        self.assertEqual(self.client.get("/api/customer/map").json()["total"], 1)
        self.assertEqual(self.client.get("/api/customer/analytics").json()["by_month"][0]["count"], 1)
        self.client.post("/api/auth/logout", headers={"X-CSRF-Token": csrf})
        self.register_and_verify("second@example.org")
        self.login("second@example.org")
        self.assertEqual(self.client.get(f"/api/customer/tests/{test_id}").status_code, 404)
        self.assertEqual(self.client.get("/api/customer/map").json()["total"], 0)
        self.assertEqual(self.client.get("/api/admin/dashboard").status_code, 403)

    def test_state_change_requires_csrf_bound_to_session(self):
        self.register_and_verify("csrf@example.org")
        self.login("csrf@example.org")
        response = self.client.patch("/api/customer/profile", json={"full_name": "Changed Name"})
        self.assertEqual(response.status_code, 403)

    def test_live_server_frontend_origin_is_allowed_by_default(self):
        response = self.client.options("/api/health", headers={
            "Origin": "http://127.0.0.1:5500",
            "Access-Control-Request-Method": "GET",
        })
        self.assertEqual(response.headers.get("access-control-allow-origin"), "http://127.0.0.1:5500")

    def test_portal_selection_is_checked_against_server_role(self):
        self.register_and_verify("portal@example.org")
        response = self.client.post("/api/auth/login", json={"email": "portal@example.org", "password": "correct horse battery", "portal": "ADMIN"})
        self.assertEqual(response.status_code, 403)

    def test_bootstrap_owner_address_cannot_publicly_register(self):
        previous_bootstrap = os.environ.get("BOOTSTRAP_OWNER_EMAIL")
        os.environ["BOOTSTRAP_OWNER_EMAIL"] = "owner@example.org"
        try:
            response = self.client.post("/api/auth/register", json=registration_payload("OWNER@example.org"))
            self.assertEqual(response.status_code, 409)
        finally:
            if previous_bootstrap is None:
                os.environ.pop("BOOTSTRAP_OWNER_EMAIL", None)
            else:
                os.environ["BOOTSTRAP_OWNER_EMAIL"] = previous_bootstrap

    def test_provisioned_admin_can_access_platform_data_and_customer_cannot_promote(self):
        self.register_and_verify("reporting-customer@example.org")
        customer_csrf = self.login("reporting-customer@example.org")
        test_id = self.create_sample(customer_csrf)
        self.client.post("/api/auth/logout", headers={"X-CSRF-Token": customer_csrf})
        db = main.get_db()
        admin_id = main.new_id("usr_")
        secret = "JBSWY3DPEHPK3PXP"
        recovery = main.token_hash("test-recovery-code")
        db.execute("INSERT INTO users(id,email,password_hash,role,email_verified,mfa_secret_enc,mfa_enabled,recovery_codes_json,created_at) VALUES(?,?,?,'ADMIN',1,?,1,?,?)", (admin_id, "admin@example.org", main.password_hash("correct horse battery"), main.encrypt_mfa_secret(secret), __import__("json").dumps([recovery]), main.iso()))
        db.execute("INSERT INTO admin_profiles(user_id,full_name,owner_title,updated_at) VALUES(?,?,?,?)", (admin_id, "QuantLite Owner", "Founder", main.iso()))
        db.commit(); db.close()
        missing_mfa = self.client.post("/api/auth/login", json={"email": "admin@example.org", "password": "correct horse battery", "portal": "ADMIN"})
        self.assertEqual(missing_mfa.status_code, 422)
        csrf = self.login("admin@example.org", "ADMIN", main.totp_code(secret))
        self.assertEqual(self.client.get("/api/admin/dashboard").status_code, 200)
        customer_list = self.client.get("/api/admin/customers?q=reporting-customer").json()
        self.assertEqual(customer_list["total"], 1)
        customer_user_id = customer_list["items"][0]["user_id"]
        self.assertEqual(self.client.get(f"/api/admin/customers/{customer_user_id}").json()["tests"][0]["id"], test_id)
        self.assertEqual(self.client.get("/api/admin/tests?state=North&status=PENDING").json()["total"], 1)
        self.assertEqual(self.client.get("/api/admin/regions?city=Harbor%20City").json()["total"], 1)
        self.assertEqual(self.client.get("/api/admin/map").json()["total"], 1)
        self.assertIn("text/csv", self.client.get("/api/admin/tests/export.csv").headers["content-type"])
        updated = self.client.patch("/api/admin/profile", headers={"X-CSRF-Token": csrf}, json={"full_name": "Owner Updated"})
        self.assertEqual(updated.status_code, 200, updated.text)
        self.assertEqual(updated.json()["profile"]["full_name"], "Owner Updated")
        self.assertEqual(self.client.get("/api/customer/dashboard").status_code, 403)
        self.assertTrue(self.client.get("/api/admin/audit/verify").json()["valid"])

    def test_founder_recovery_code_is_single_use_and_audit_chain_detects_tampering(self):
        db = main.get_db()
        user_id = main.new_id("usr_")
        secret = "JBSWY3DPEHPK3PXP"
        db.execute("INSERT INTO users(id,email,password_hash,role,email_verified,mfa_secret_enc,mfa_enabled,recovery_codes_json,created_at) VALUES(?,?,?,'ADMIN',1,?,1,?,?)", (user_id, "founder@example.org", main.password_hash("correct horse battery"), main.encrypt_mfa_secret(secret), __import__("json").dumps([main.token_hash("once-only-recovery")]), main.iso()))
        db.execute("INSERT INTO admin_profiles(user_id,full_name,updated_at) VALUES(?,?,?)", (user_id, "Founder", main.iso()))
        db.commit(); db.close()
        first = self.client.post("/api/auth/login", json={"email": "founder@example.org", "password": "correct horse battery", "portal": "ADMIN", "mfa_code": "once-only-recovery"})
        self.assertEqual(first.status_code, 200, first.text)
        self.client.post("/api/auth/logout", headers={"X-CSRF-Token": first.json()["csrf_token"]})
        second = self.client.post("/api/auth/login", json={"email": "founder@example.org", "password": "correct horse battery", "portal": "ADMIN", "mfa_code": "once-only-recovery"})
        self.assertEqual(second.status_code, 401)
        db = main.get_db()
        main.write_audit(db, user_id, "TEST_EVENT", "security")
        db.commit()
        self.assertTrue(main.verify_audit_chain(db)["valid"])
        row = db.execute("SELECT id FROM audit_logs ORDER BY created_at LIMIT 1").fetchone()
        db.execute("DROP TRIGGER audit_logs_no_update")
        db.execute("UPDATE audit_logs SET action='TAMPERED' WHERE id=?", (row["id"],))
        db.commit()
        self.assertFalse(main.verify_audit_chain(db)["valid"])
        db.close()


if __name__ == "__main__":
    unittest.main()
