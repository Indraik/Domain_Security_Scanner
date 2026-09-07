import sys
import os
import unittest

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from app.services.email_security import (
    analyze_spf,
    analyze_dmarc,
    classify_txt,
    calculate_email_security_score,
)


class TestEmailSecurity(unittest.TestCase):
    def test_analyze_spf(self):
        self.assertEqual(analyze_spf(["v=spf1 include:_spf.google.com -all"]), "Strong")
        self.assertEqual(analyze_spf(["v=spf1 include:_spf.google.com ~all"]), "SoftFail")
        self.assertEqual(analyze_spf(["v=spf1 +all"]), "Weak")
        self.assertEqual(analyze_spf(["unrelated txt record"]), "Missing")

    def test_analyze_dmarc(self):
        self.assertEqual(analyze_dmarc(["v=DMARC1; p=reject; rua=mailto:d@example.com"]), "Strong")
        self.assertEqual(analyze_dmarc(["v=DMARC1; p=quarantine;"]), "Medium")
        self.assertEqual(analyze_dmarc(["v=DMARC1; p=none;"]), "Weak")
        self.assertEqual(analyze_dmarc([]), "Missing")

    def test_classify_txt(self):
        records = [
            "v=spf1 -all",
            "google-site-verification=xyz",
            "v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQ"
        ]
        spf, dkim, other = classify_txt(records)
        self.assertEqual(len(spf), 1)
        self.assertEqual(len(dkim), 1)
        self.assertEqual(len(other), 1)

    def test_calculate_email_security_score_full(self):
        score, grade, reasons = calculate_email_security_score(
            mx=["mail.example.com"],
            dmarc=["v=DMARC1; p=reject;"],
            spf_status="Strong",
            dkim=["v=DKIM1;"]
        )
        self.assertEqual(score, 100)
        self.assertEqual(grade, "Strong")
        self.assertEqual(len(reasons), 4)

    def test_calculate_email_security_score_missing(self):
        score, grade, reasons = calculate_email_security_score(
            mx=[],
            dmarc=[],
            spf_status="Missing",
            dkim=[]
        )
        self.assertEqual(score, 0)
        self.assertEqual(grade, "Weak")


if __name__ == "__main__":
    unittest.main()
