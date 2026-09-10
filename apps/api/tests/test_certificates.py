import unittest
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

from cloudnative_security.certificate_inspector import (
    inspect_certificate,
    parse_control_plane_certificate_paths,
)


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

    def test_static_pod_parser_allows_public_paths_only(self):
        entries = parse_control_plane_certificate_paths(
            [
                "kube-apiserver",
                "--tls-cert-file=/etc/kubernetes/server.crt",
                "--tls-private-key-file=/etc/kubernetes/server.key",
                "--client-ca-file",
                "/etc/kubernetes/ca.crt",
                "--etcd-keyfile=/etc/kubernetes/etcd.key",
                "--etcd-certfile=/etc/kubernetes/etcd-client.crt",
            ]
        )
        self.assertEqual(["tls-cert-file", "client-ca-file", "etcd-certfile"], [item.flag for item in entries])
        self.assertNotIn("key", str([item.to_dict() for item in entries]))

    def test_expiry_san_and_weak_key_checks_are_explainable(self):
        after = (datetime.now(timezone.utc) + timedelta(days=10)).strftime("%b %d %H:%M:%S %Y GMT")
        decoded = {
            "notAfter": after,
            "subjectAltName": (("DNS", "*.demo.example"),),
            "signatureAlgorithm": "sha1WithRSAEncryption",
            "publicKeyAlgorithm": "RSA",
            "publicKeySize": 1024,
        }
        with patch("cloudnative_security.certificate_inspector.ssl._ssl._test_decode_cert", return_value=decoded):
            profile = inspect_certificate(
                b"-----BEGIN CERTIFICATE-----\nX\n-----END CERTIFICATE-----",
                expected_sans=["api.demo.example"],
            )
        self.assertTrue(profile.expires_within_30_days)
        self.assertTrue(profile.san_covered)
        self.assertTrue(profile.weak_signature)
        self.assertTrue(profile.weak_public_key)
        self.assertIsNotNone(profile.weak_signature_reason)
        self.assertIsNotNone(profile.weak_public_key_reason)


if __name__ == "__main__":
    unittest.main()
