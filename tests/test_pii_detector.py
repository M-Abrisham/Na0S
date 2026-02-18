"""Tests for src/layer0/pii_detector.py — PII/secrets pre-screening.

Run: python3 -m unittest tests/test_pii_detector.py -v
Uses only well-known test numbers — NEVER real PII.
"""

import os
import sys
import unittest


from na0s.layer0.pii_detector import (
    PiiScanResult,
    scan_pii,
    _luhn_check,
    _redact,
)


class TestLuhnCheck(unittest.TestCase):
    def test_valid_visa(self):
        self.assertTrue(_luhn_check("4111111111111111"))

    def test_valid_mastercard(self):
        self.assertTrue(_luhn_check("5500000000000004"))

    def test_valid_amex(self):
        self.assertTrue(_luhn_check("378282246310005"))

    def test_valid_discover(self):
        self.assertTrue(_luhn_check("6011111111111117"))

    def test_invalid_number(self):
        self.assertFalse(_luhn_check("4111111111111112"))


class TestRedact(unittest.TestCase):
    def test_long_value(self):
        self.assertEqual(_redact("4111111111111111"), "4111***")

    def test_short_value(self):
        self.assertEqual(_redact("abc"), "a***")

    def test_five_char_value(self):
        self.assertEqual(_redact("abcde"), "abcd***")


class TestCreditCardDetection(unittest.TestCase):
    def test_visa_plain(self):
        result = scan_pii("My card is 4111111111111111 please charge it")
        self.assertTrue(result.has_pii)
        self.assertIn("credit_card", result.pii_types_found)
        self.assertIn("pii_credit_card", result.anomaly_flags)

    def test_visa_with_dashes(self):
        result = scan_pii("Card: 4111-1111-1111-1111")
        self.assertTrue(result.has_pii)
        self.assertIn("credit_card", result.pii_types_found)

    def test_visa_with_spaces(self):
        result = scan_pii("Card: 4111 1111 1111 1111")
        self.assertTrue(result.has_pii)

    def test_mastercard(self):
        result = scan_pii("MC: 5500000000000004")
        self.assertTrue(result.has_pii)
        self.assertIn("credit_card", result.pii_types_found)

    def test_amex(self):
        result = scan_pii("Amex: 378282246310005")
        self.assertTrue(result.has_pii)

    def test_discover(self):
        result = scan_pii("Discover: 6011111111111117")
        self.assertTrue(result.has_pii)

    def test_invalid_luhn_rejected(self):
        result = scan_pii("Card: 4111111111111112")
        self.assertNotIn("credit_card", result.pii_types_found)

    def test_short_number_no_match(self):
        result = scan_pii("Order 12345 is ready")
        self.assertNotIn("credit_card", result.pii_types_found)


class TestSSNDetection(unittest.TestCase):
    def test_valid_ssn(self):
        result = scan_pii("SSN: 123-45-6789")
        self.assertTrue(result.has_pii)
        self.assertIn("ssn", result.pii_types_found)
        self.assertIn("pii_ssn", result.anomaly_flags)

    def test_area_000_rejected(self):
        result = scan_pii("SSN: 000-45-6789")
        self.assertNotIn("ssn", result.pii_types_found)

    def test_area_666_rejected(self):
        result = scan_pii("SSN: 666-45-6789")
        self.assertNotIn("ssn", result.pii_types_found)

    def test_area_900_rejected(self):
        result = scan_pii("SSN: 900-45-6789")
        self.assertNotIn("ssn", result.pii_types_found)

    def test_group_00_rejected(self):
        result = scan_pii("SSN: 123-00-6789")
        self.assertNotIn("ssn", result.pii_types_found)

    def test_serial_0000_rejected(self):
        result = scan_pii("SSN: 123-45-0000")
        self.assertNotIn("ssn", result.pii_types_found)

    def test_no_dashes_no_match(self):
        result = scan_pii("Number 123456789 is just digits")
        self.assertNotIn("ssn", result.pii_types_found)


class TestEmailDetection(unittest.TestCase):
    def test_simple_email(self):
        result = scan_pii("Contact: user@example.com")
        self.assertTrue(result.has_pii)
        self.assertIn("email", result.pii_types_found)

    def test_email_with_plus(self):
        result = scan_pii("user+tag@gmail.com")
        self.assertTrue(result.has_pii)

    def test_no_at_sign(self):
        result = scan_pii("This is not an email address")
        self.assertNotIn("email", result.pii_types_found)


class TestPhoneDetection(unittest.TestCase):
    def test_dashed_phone(self):
        result = scan_pii("Call me at 555-123-4567")
        self.assertTrue(result.has_pii)
        self.assertIn("phone", result.pii_types_found)

    def test_dotted_phone(self):
        result = scan_pii("Phone: 555.123.4567")
        self.assertTrue(result.has_pii)

    def test_parenthesized_phone(self):
        result = scan_pii("Phone: (555) 123-4567")
        self.assertTrue(result.has_pii)

    def test_short_number_no_match(self):
        result = scan_pii("Call 911 now")
        self.assertNotIn("phone", result.pii_types_found)


class TestAPIKeyDetection(unittest.TestCase):
    def test_aws_access_key(self):
        result = scan_pii("Key: AKIAIOSFODNN7EXAMPLE")
        self.assertTrue(result.has_pii)
        self.assertIn("api_key", result.pii_types_found)
        self.assertIn("pii_api_key", result.anomaly_flags)

    def test_github_personal_token(self):
        token = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij"
        result = scan_pii("Token: {}".format(token))
        self.assertTrue(result.has_pii)

    def test_generic_hex_40_chars(self):
        hex_str = "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0"
        result = scan_pii("Hash: {}".format(hex_str))
        self.assertTrue(result.has_pii)

    def test_generic_hex_low_diversity_rejected(self):
        hex_str = "a" * 40
        result = scan_pii("Value: {}".format(hex_str))
        found = [d for d in result.details if d["subtype"] == "generic_hex"]
        self.assertEqual(len(found), 0)


class TestIPv4Detection(unittest.TestCase):
    def test_valid_ipv4(self):
        result = scan_pii("Connect to 192.168.1.100")
        self.assertTrue(result.has_pii)
        self.assertIn("ipv4", result.pii_types_found)

    def test_invalid_octet(self):
        result = scan_pii("Not IP: 999.999.999.999")
        self.assertNotIn("ipv4", result.pii_types_found)


class TestNoPII(unittest.TestCase):
    def test_empty_string(self):
        result = scan_pii("")
        self.assertFalse(result.has_pii)
        self.assertEqual(result.pii_count, 0)

    def test_normal_text(self):
        result = scan_pii("The quick brown fox jumps over the lazy dog.")
        self.assertFalse(result.has_pii)

    def test_none_input(self):
        result = scan_pii(None)
        self.assertFalse(result.has_pii)


class TestMixedPII(unittest.TestCase):
    def test_multiple_types(self):
        text = (
            "SSN: 123-45-6789, Card: 4111111111111111, "
            "Email: john@example.com, Phone: 555-123-4567"
        )
        result = scan_pii(text)
        self.assertTrue(result.has_pii)
        self.assertIn("ssn", result.pii_types_found)
        self.assertIn("credit_card", result.pii_types_found)
        self.assertIn("email", result.pii_types_found)
        self.assertIn("phone", result.pii_types_found)
        self.assertGreaterEqual(result.pii_count, 4)


class TestRedactionSafety(unittest.TestCase):
    def test_credit_card_redacted(self):
        result = scan_pii("Card: 4111111111111111")
        for d in result.details:
            if d["type"] == "credit_card":
                self.assertNotIn("4111111111111111", d["redacted_value"])
                self.assertTrue(d["redacted_value"].endswith("***"))

    def test_ssn_redacted(self):
        result = scan_pii("SSN: 123-45-6789")
        for d in result.details:
            if d["type"] == "ssn":
                self.assertNotIn("123-45-6789", d["redacted_value"])

    def test_no_full_pii_in_details(self):
        text = "SSN: 123-45-6789, Card: 4111111111111111"
        result = scan_pii(text)
        pii_values = ["123-45-6789", "4111111111111111"]
        for d in result.details:
            for val in d.values():
                for pii in pii_values:
                    self.assertNotIn(pii, str(val))


class TestSanitizerIntegration(unittest.TestCase):
    def test_pii_flags_in_sanitizer(self):
        from na0s.layer0.sanitizer import layer0_sanitize
        result = layer0_sanitize("Please charge 4111111111111111 for the order")
        self.assertFalse(result.rejected)
        self.assertIn("pii_credit_card", result.anomaly_flags)
        self.assertIn("pii_scan", result.source_metadata)

    def test_no_pii_no_flags(self):
        from na0s.layer0.sanitizer import layer0_sanitize
        result = layer0_sanitize("What is the weather today?")
        self.assertFalse(result.rejected)
        self.assertNotIn("pii_credit_card", result.anomaly_flags)

    def test_ssn_in_sanitizer(self):
        from na0s.layer0.sanitizer import layer0_sanitize
        result = layer0_sanitize("My SSN is 123-45-6789")
        self.assertIn("pii_ssn", result.anomaly_flags)


if __name__ == "__main__":
    unittest.main()
