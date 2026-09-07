import sys
import os
import unittest

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from app import create_app


class TestApiAndWebRoutes(unittest.TestCase):
    def setUp(self):
        self.app = create_app()
        self.app.config["TESTING"] = True
        self.client = self.app.test_client()

    def test_index_route(self):
        response = self.client.get("/")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Domain Security", response.data)

    def test_api_scan_invalid_domain(self):
        response = self.client.post("/api/scan", json={"domain": "invalid..domain"})
        self.assertEqual(response.status_code, 400)
        data = response.get_json()
        self.assertFalse(data["success"])
        self.assertIn("error", data)

    def test_api_pdf_empty(self):
        response = self.client.post("/api/report/pdf", json={})
        self.assertEqual(response.status_code, 400)


if __name__ == "__main__":
    unittest.main()
