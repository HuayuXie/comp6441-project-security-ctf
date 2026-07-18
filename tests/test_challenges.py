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
        locked = self.client.get("/defence")
        self.assertIn(b"Challenge 1 defence locked", locked.data)

        self.client.set_cookie("role", "admin")
        vulnerable = self.client.get("/challenge/1")
        self.assertIn(b"FLAG{client_side_role_is_not_auth}", vulnerable.data)

        progress = self.client.get("/")
        self.assertIn(b"Challenge 1: Cookie Role Bypass", progress.data)
        self.assertIn(b"Completed", progress.data)

        unlocked = self.client.get("/defence")
        self.assertIn(b"Open secure comparison", unlocked.data)
        self.assertNotIn(b"Challenge 1 defence locked", unlocked.data)

        secure = self.client.get("/secure/challenge/1")
        self.assertIn(b"has role <strong>user</strong>", secure.data)
        self.assertNotIn(b"FLAG{client_side_role_is_not_auth}", secure.data)

    def test_reflected_xss_and_encoded_output(self):
        payload = "<script>alert(1)</script>"
        vulnerable = self.client.get("/challenge/2", query_string={"q": payload})
        self.assertIn(payload.encode(), vulnerable.data)
        self.assertIn(b"FLAG{xss_needs_output_encoding}", vulnerable.data)
        self.assertIn(b"Return home to view your updated progress.", vulnerable.data)

        secure = self.client.get("/secure/challenge/2", query_string={"q": payload})
        self.assertNotIn(payload.encode(), secure.data)
        self.assertIn(b"&lt;script&gt;alert(1)&lt;/script&gt;", secure.data)
        self.assertIn("script-src 'self'", secure.headers["Content-Security-Policy"])

    def test_path_traversal_and_allowlist(self):
        payload = "../secret/flag.txt"
        vulnerable = self.client.get("/challenge/3", query_string={"file": payload})
        self.assertIn(b"FLAG{path_traversal_hidden_file_found}", vulnerable.data)
        self.assertIn(b"Return home to view your updated progress.", vulnerable.data)

        secure = self.client.get("/secure/challenge/3", query_string={"file": payload})
        self.assertIn(b"Blocked: filename is not in the allowlist.", secure.data)
        self.assertNotIn(b"FLAG{path_traversal_hidden_file_found}", secure.data)

    def test_sql_injection_and_parameterised_query(self):
        payload = {"username": "student", "password": "' OR '1'='1"}
        vulnerable = self.client.post("/challenge/4", data=payload)
        self.assertIn(b"FLAG{sql_queries_need_parameters}", vulnerable.data)
        self.assertIn(b"Return home to view your updated progress.", vulnerable.data)

        secure = self.client.post("/secure/challenge/4", data=payload)
        self.assertIn(b"Login failed. SQL injection input is treated as data.", secure.data)
        self.assertNotIn(b"FLAG{sql_queries_need_parameters}", secure.data)

        progress = self.client.get("/")
        self.assertGreaterEqual(progress.data.count(b"Completed"), 1)

    def test_progressive_hints_and_progress_reset(self):
        challenge1 = self.client.get("/challenge/1")
        self.assertIn(b"Hint 1", challenge1.data)
        self.assertIn(b"Show Hint 2", challenge1.data)
        self.assertIn(b"confirm the change, then refresh", challenge1.data)

        self.client.set_cookie("role", "admin")
        self.client.get("/challenge/1")
        self.client.post("/progress/reset")
        home = self.client.get("/")
        self.assertNotIn(b"Challenge 1 defence locked", home.data)
        defence = self.client.get("/defence")
        self.assertIn(b"Challenge 1 defence locked", defence.data)

    def test_all_challenge_pages_have_two_hint_levels(self):
        for challenge_id in range(1, 5):
            page = self.client.get(f"/challenge/{challenge_id}")
            self.assertIn(b"Hint 1", page.data)
            self.assertIn(b"Show Hint 2", page.data)

    def test_secure_routes_are_locked_on_the_server(self):
        for challenge_id in range(1, 5):
            locked = self.client.get(f"/secure/challenge/{challenge_id}")
            self.assertEqual(locked.status_code, 403)
            self.assertIn(f"Challenge {challenge_id} Defence Locked".encode(), locked.data)

        self.client.get("/challenge/2", query_string={"q": "<script>alert(1)</script>"})
        unlocked = self.client.get("/secure/challenge/2")
        still_locked = self.client.get("/secure/challenge/1")
        self.assertEqual(unlocked.status_code, 200)
        self.assertEqual(still_locked.status_code, 403)

    def test_xss_keyword_without_markup_does_not_award_flag(self):
        result = self.client.get("/challenge/2", query_string={"q": "alert"})
        self.assertNotIn(b"FLAG{xss_needs_output_encoding}", result.data)

        progress = self.client.get("/")
        self.assertIn(b"Challenge 2: Reflected XSS Search Page", progress.data)
        self.assertEqual(progress.data.count(b">Completed<"), 0)

    def test_normal_sql_login_does_not_award_injection_flag(self):
        result = self.client.post(
            "/challenge/4",
            data={"username": "student", "password": "password123"},
        )
        self.assertIn(b"Normal login successful.", result.data)
        self.assertNotIn(b"FLAG{sql_queries_need_parameters}", result.data)

        progress = self.client.get("/")
        self.assertEqual(progress.data.count(b">Completed<"), 0)

    def test_progress_reset_requires_post(self):
        get_result = self.client.get("/progress/reset")
        self.assertEqual(get_result.status_code, 405)

        post_result = self.client.post("/progress/reset")
        self.assertEqual(post_result.status_code, 302)

    def test_all_challenges_complete_and_unlock_defences(self):
        self.client.set_cookie("role", "admin")
        self.client.get("/challenge/1")
        self.client.get("/challenge/2", query_string={"q": "<script>alert(1)</script>"})
        self.client.get("/challenge/3", query_string={"file": "../secret/flag.txt"})
        self.client.post("/challenge/4", data={"username": "student", "password": "' OR '1'='1"})

        home = self.client.get("/")
        self.assertEqual(home.data.count(b">Completed<"), 4)

        defence = self.client.get("/defence")
        self.assertNotIn(b"defence locked", defence.data)
        self.assertEqual(defence.data.count(b"Open secure comparison"), 4)


if __name__ == "__main__":
    unittest.main()
