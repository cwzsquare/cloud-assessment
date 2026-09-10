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

    def test_resource_derived_fields_and_kms_configuration_summary(self):
        config = {
            "resources": [{
                "resources": ["secrets", "configmaps"],
                "providers": [
                    {"kms": {
                        "name": "provider-a",
                        "apiVersion": "v2",
                        "endpoint": "unix:///var/run/kms.sock",
                        "timeout": "3s",
                        "cachesize": 100,
                        "online": True,
                        "key": "PRIVATE",
                    }},
                    {"identity": {}},
                ],
            }],
        }
        rule = parse_encryption_config(config).rules[0]
        self.assertTrue(rule.covers_secrets)
        self.assertEqual("kms", rule.active_provider)
        self.assertEqual(["identity"], rule.fallback_providers)
        self.assertFalse(rule.identity_first)
        self.assertTrue(rule.identity_last)
        self.assertTrue(rule.encrypted_write_enabled)
        self.assertTrue(rule.key_rotation_structure["rotation_safe"])
        payload = str(rule.to_dict())
        self.assertNotIn("PRIVATE", payload)
        self.assertNotIn("online", payload)

    def test_missing_rules_are_unknown(self):
        self.assertEqual("UNKNOWN", parse_encryption_config({}).status)


if __name__ == "__main__":
    unittest.main()
