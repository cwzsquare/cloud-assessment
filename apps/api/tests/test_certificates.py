import unittest
from unittest.mock import patch

from cloudnative_security.certificate_inspector import inspect_certificate


class CertificateInspectorTests(unittest.TestCase):
    def test_invalid_certificate_is_unknown_without_raising(self):
        profile = inspect_certificate(b"not a certificate")
        self.assertEqual("UNKNOWN", profile.status)
        self.assertIsNotNone(profile.error)
        self.assertFalse(hasattr(profile, "private_key"))

    def test_public_metadata_and_sans_are_returned(self):
        decoded = {
            "subject": ((('commonName', 'demo'),),),
            "issuer": ((('commonName', 'ca'),),),
            "serialNumber": "01",
            "notBefore": "Jan 01 00:00:00 2030 GMT",
            "notAfter": "Jan 01 00:00:00 2031 GMT",
            "subjectAltName": (("DNS", "demo.example"),),
            "version": 3,
        }
        with patch("cloudnative_security.certificate_inspector.ssl._ssl._test_decode_cert", return_value=decoded):
            profile = inspect_certificate(b"-----BEGIN CERTIFICATE-----\nX\n-----END CERTIFICATE-----")
        self.assertEqual("PASS", profile.status)
        self.assertIn("DNS:demo.example", profile.sans)
        self.assertEqual("commonName=demo", profile.subject)


if __name__ == "__main__":
    unittest.main()
