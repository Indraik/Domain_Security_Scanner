import sys
import os
import unittest

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from app.utils.validators import sanitize_domain, validate_domain


class TestValidators(unittest.TestCase):
    def test_sanitize_domain(self):
        self.assertEqual(sanitize_domain("https://example.com/test?query=1"), "example.com")
        self.assertEqual(sanitize_domain("http://sub.domain.org:8080/path"), "sub.domain.org")
        self.assertEqual(sanitize_domain("   google.com   "), "google.com")
        self.assertEqual(sanitize_domain("cloudflare.com/"), "cloudflare.com")

    def test_validate_domain_valid(self):
        is_valid, domain = validate_domain("example.com")
        self.assertTrue(is_valid)
        self.assertEqual(domain, "example.com")

        is_valid, domain = validate_domain("https://sub-domain.co.uk")
        self.assertTrue(is_valid)
        self.assertEqual(domain, "sub-domain.co.uk")

    def test_validate_domain_invalid(self):
        is_valid, err = validate_domain("")
        self.assertFalse(is_valid)
        self.assertIn("empty", err.lower())

        is_valid, err = validate_domain("not_a_domain")
        self.assertFalse(is_valid)
        self.assertIn("not a valid domain", err.lower())


if __name__ == "__main__":
    unittest.main()
