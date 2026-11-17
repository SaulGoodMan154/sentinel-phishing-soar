#!/usr/bin/env python3
"""
Unit tests for SOAR Phishing Triage Engine (phish_triage.py)
"""

import os
import unittest
from pathlib import Path
from phish_triage import (
    defang_url,
    defang_ip,
    EmailTriageAnalyzer,
    generate_markdown_report,
    ThreatIntelligenceEnricher
)

SAMPLES_DIR = Path(__file__).resolve().parent.parent / "samples"


class TestDefangUtilities(unittest.TestCase):
    def test_defang_url(self):
        self.assertEqual(
            defang_url("http://malicious.example.com/login"),
            "hxxp://malicious[.]example[.]com/login"
        )
        self.assertEqual(
            defang_url("https://45.33.32.156/owa"),
            "hxxps://45[.]33[.]32[.]156/owa"
        )
        self.assertEqual(defang_url(""), "")

    def test_defang_ip(self):
        self.assertEqual(defang_ip("192.168.1.1"), "192[.]168[.]1[.]1")
        self.assertEqual(defang_ip(""), "")


class TestSampleTriageVerdicts(unittest.TestCase):
    def setUp(self):
        self.sample01_path = SAMPLES_DIR / "01_suspicious_credential_harvest.eml"
        self.sample02_path = SAMPLES_DIR / "02_benign_newsletter.eml"
        self.sample03_path = SAMPLES_DIR / "03_suspicious_invoice_zip.eml"

        self.assertTrue(self.sample01_path.exists(), f"Sample 1 missing: {self.sample01_path}")
        self.assertTrue(self.sample02_path.exists(), f"Sample 2 missing: {self.sample02_path}")
        self.assertTrue(self.sample03_path.exists(), f"Sample 3 missing: {self.sample03_path}")

    def test_sample_01_credential_harvest_is_malicious(self):
        with open(self.sample01_path, "rb") as f:
            content = f.read()

        analyzer = EmailTriageAnalyzer(content, filename=str(self.sample01_path))
        result = analyzer.evaluate_verdict()

        self.assertEqual(result["verdict"], "malicious")
        self.assertGreaterEqual(result["risk_score"], 50)

        # Verify authentication failures
        auth = result["extracted"]["authentication"]
        self.assertEqual(auth["spf"], "fail")
        self.assertEqual(auth["dkim"], "fail")
        self.assertEqual(auth["dmarc"], "fail")

        # Verify attachment detection
        attachments = result["extracted"]["attachments"]
        self.assertEqual(len(attachments), 1)
        self.assertEqual(attachments[0]["extension"], ".exe")
        self.assertTrue(attachments[0]["is_critical_risk"])

        # Verify IP URL detection
        urls = result["extracted"]["urls"]
        ip_urls = [u for u in urls if u["is_ip_url"]]
        self.assertGreater(len(ip_urls), 0)

        # Verify key reason tags
        reasons_str = " ".join(result["reasons"])
        self.assertIn("spf_fail", reasons_str)
        self.assertIn("executable_attachment", reasons_str)
        self.assertIn("ip_based_url", reasons_str)

    def test_sample_02_newsletter_is_likely_benign(self):
        with open(self.sample02_path, "rb") as f:
            content = f.read()

        analyzer = EmailTriageAnalyzer(content, filename=str(self.sample02_path))
        result = analyzer.evaluate_verdict()

        self.assertEqual(result["verdict"], "likely_benign")
        self.assertLess(result["risk_score"], 25)

        # Verify auth pass
        auth = result["extracted"]["authentication"]
        self.assertEqual(auth["spf"], "pass")
        self.assertEqual(auth["dkim"], "pass")
        self.assertEqual(auth["dmarc"], "pass")

        # No attachments
        self.assertEqual(len(result["extracted"]["attachments"]), 0)

        # Legitimate HTTPS URLs
        urls = result["extracted"]["urls"]
        self.assertGreater(len(urls), 0)
        for u in urls:
            self.assertFalse(u["is_ip_url"])
            self.assertFalse(u["is_suspicious_tld"])

    def test_sample_03_invoice_zip_is_malicious_or_suspicious(self):
        with open(self.sample03_path, "rb") as f:
            content = f.read()

        analyzer = EmailTriageAnalyzer(content, filename=str(self.sample03_path))
        result = analyzer.evaluate_verdict()

        # Expected: malicious or suspicious (softfail + zip + mismatch)
        self.assertIn(result["verdict"], ["malicious", "suspicious"])
        self.assertGreaterEqual(result["risk_score"], 25)

        auth = result["extracted"]["authentication"]
        self.assertEqual(auth["spf"], "softfail")

        # Verify zip attachment detected
        attachments = result["extracted"]["attachments"]
        self.assertEqual(len(attachments), 1)
        self.assertEqual(attachments[0]["extension"], ".zip")
        self.assertTrue(attachments[0]["is_suspicious_archive"])

        # Verify sender header mismatch
        reasons_str = " ".join(result["reasons"])
        self.assertIn("spf_softfail", reasons_str)
        self.assertIn("sender_reply_to_mismatch", reasons_str)


class TestReportGeneration(unittest.TestCase):
    def test_markdown_report_formatting(self):
        sample_path = SAMPLES_DIR / "01_suspicious_credential_harvest.eml"
        with open(sample_path, "rb") as f:
            content = f.read()

        analyzer = EmailTriageAnalyzer(content, filename=str(sample_path))
        result = analyzer.evaluate_verdict()
        md = generate_markdown_report(result)

        self.assertIn("# Phishing Triage Report", md)
        self.assertIn("🔴 **MALICIOUS**", md)
        self.assertIn("## Key Triage Triggers", md)
        self.assertIn("## Authentication Breakdown", md)
        self.assertIn("## Attachments", md)
        self.assertIn("Security_Update_Tool.exe", md)
        self.assertIn("hxxp://45[.]33[.]32[.]156/owa/auth/login[.]html", md)


class TestEnricherSafeguards(unittest.TestCase):
    def test_private_ip_detection(self):
        enricher = ThreatIntelligenceEnricher()
        self.assertTrue(enricher._is_private_ip("192.168.1.100"))
        self.assertTrue(enricher._is_private_ip("10.0.0.5"))
        self.assertTrue(enricher._is_private_ip("172.16.0.1"))
        self.assertTrue(enricher._is_private_ip("127.0.0.1"))
        self.assertFalse(enricher._is_private_ip("8.8.8.8"))
        self.assertFalse(enricher._is_private_ip("185.220.101.5"))


if __name__ == "__main__":
    unittest.main()
