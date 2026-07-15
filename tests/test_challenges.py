import tempfile
import unittest
from pathlib import Path

import app as ctf_app


class ChallengeTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        ctf_app.DB_PATH = Path(self.temp_dir.name) / "test.db"
        ctf_app.app.config.update(TESTING=True, SECRET_KEY="test-secret")
        ctf_app.init_db()
        self.client = ctf_app.app.test_client()

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_cookie_role_bypass_and_backend_role_check(self):
        self.client.set_cookie("role", "admin")
        vulnerable = self.client.get("/challenge/1")
        self.assertIn(b"FLAG{client_side_role_is_not_auth}", vulnerable.data)

        secure = self.client.get("/secure/challenge/1")
        self.assertIn(b"has role <strong>user</strong>", secure.data)
        self.assertNotIn(b"FLAG{client_side_role_is_not_auth}", secure.data)

    def test_reflected_xss_and_encoded_output(self):
        payload = "<script>alert(1)</script>"
        vulnerable = self.client.get("/challenge/2", query_string={"q": payload})
        self.assertIn(payload.encode(), vulnerable.data)
        self.assertIn(b"FLAG{xss_needs_output_encoding}", vulnerable.data)

        secure = self.client.get("/secure/challenge/2", query_string={"q": payload})
        self.assertNotIn(payload.encode(), secure.data)
        self.assertIn(b"&lt;script&gt;alert(1)&lt;/script&gt;", secure.data)
        self.assertIn("script-src 'self'", secure.headers["Content-Security-Policy"])

    def test_path_traversal_and_allowlist(self):
        payload = "../secret/flag.txt"
        vulnerable = self.client.get("/challenge/3", query_string={"file": payload})
        self.assertIn(b"FLAG{path_traversal_hidden_file_found}", vulnerable.data)

        secure = self.client.get("/secure/challenge/3", query_string={"file": payload})
        self.assertIn(b"Blocked: filename is not in the allowlist.", secure.data)
        self.assertNotIn(b"FLAG{path_traversal_hidden_file_found}", secure.data)

    def test_sql_injection_and_parameterised_query(self):
        payload = {"username": "student", "password": "' OR '1'='1"}
        vulnerable = self.client.post("/challenge/4", data=payload)
        self.assertIn(b"FLAG{sql_queries_need_parameters}", vulnerable.data)

        secure = self.client.post("/secure/challenge/4", data=payload)
        self.assertIn(b"Login failed. SQL injection input is treated as data.", secure.data)
        self.assertNotIn(b"FLAG{sql_queries_need_parameters}", secure.data)


if __name__ == "__main__":
    unittest.main()
