import unittest

from cloudnative_security.encryption_config import parse_encryption_config, redact_encryption_config


class EncryptionConfigTests(unittest.TestCase):
    def test_provider_order_key_rotation_and_redaction(self):
        config = {
            "resources": [{
                "resources": ["secrets"],
                "providers": [
                    {"aescbc": {"keys": [{"name": "v2", "key": "PRIVATE"}, {"name": "v1", "key": "OLD"}]}},
                    {"identity": {}},
                ],
            }],
        }
        profile = parse_encryption_config(config)
        self.assertEqual("PASS", profile.status)
        self.assertEqual(["aescbc", "identity"], profile.provider_order)
        self.assertEqual(["v2", "v1"], profile.key_names)
        self.assertNotIn("PRIVATE", str(profile.to_dict()))
        self.assertNotIn("PRIVATE", str(redact_encryption_config(config)))

    def test_missing_rules_are_unknown(self):
        self.assertEqual("UNKNOWN", parse_encryption_config({}).status)


if __name__ == "__main__":
    unittest.main()
