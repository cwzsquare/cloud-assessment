from __future__ import annotations

import unittest

from cloudnative_security.authn_analyzers import (
    analyze_authentication_profile,
    analyze_front_proxy_authentication,
    analyze_identity_profiles,
    analyze_oidc_authentication,
    analyze_service_account_token_profile,
    analyze_webhook_authentication,
    classify_anonymous_authorization,
)


class AuthenticationProfilesTest(unittest.TestCase):
    def test_complete_authentication_and_token_profiles(self) -> None:
        args = [
            "--anonymous-auth=false",
            "--oidc-issuer-url=https://accounts.example.test",
            "--oidc-client-id=cluster",
            "--oidc-username-claim=email",
            "--oidc-groups-claim=groups",
            "--authentication-token-webhook-config-file=/etc/kubernetes/webhook.yaml",
            "--authentication-token-webhook-endpoint=https://authz.example.test/review",
            "--authentication-token-webhook-ca-file=/etc/kubernetes/ca.crt",
            "--requestheader-client-ca-file=/etc/kubernetes/front-proxy-ca.crt",
            "--requestheader-username-headers=X-Remote-User",
            "--requestheader-group-headers=X-Remote-Group",
        ]
        profile = analyze_authentication_profile(args, rbac_rows=[])
        self.assertFalse(profile.anonymous_auth)
        self.assertEqual("disabled", profile.anonymous_authorization)
        self.assertEqual("PASS", profile.oidc.status)
        self.assertEqual("PASS", profile.webhook.status)
        self.assertEqual("PASS", profile.front_proxy.status)

        workload = {
            "kind": "Pod",
            "metadata": {"name": "controller", "namespace": "platform"},
            "spec": {
                "serviceAccountName": "controller",
                "automountServiceAccountToken": False,
                "volumes": [{"name": "api-token", "projected": {"sources": [{"serviceAccountToken": {"audience": "https://kubernetes.default.svc", "expirationSeconds": 3600}}]}}],
            },
        }
        token = analyze_service_account_token_profile(workload, rbac_rows=[{"subject": {"kind": "ServiceAccount", "name": "controller", "namespace": "platform"}, "rules": [{"verbs": ["get"], "resources": ["pods"]}]}], expected_audience="https://kubernetes.default.svc")
        self.assertEqual("controller", token.service_account)
        self.assertTrue(token.projected_token)
        self.assertTrue(token.expiration_ok)
        self.assertTrue(token.audience_ok)
        self.assertEqual("aligned", token.api_permission_alignment)

    def test_bad_oidc_webhook_front_proxy_and_anonymous_binding(self) -> None:
        oidc = analyze_oidc_authentication({"oidc-issuer-url": "http://issuer.invalid", "oidc-client-id": "api"})
        self.assertEqual("FAIL", oidc.status)
        self.assertFalse(oidc.issuer_https)
        webhook = analyze_webhook_authentication({"authentication-token-webhook-endpoint": "http://authz.invalid"})
        self.assertEqual("FAIL", webhook.status)
        front_proxy = analyze_front_proxy_authentication({"requestheader-client-ca-file": "/ca", "requestheader-username-headers": "X-User", "front-proxy-endpoint": "http://proxy.invalid"})
        self.assertEqual("FAIL", front_proxy.status)
        self.assertEqual("enabled_broadly_authorized", classify_anonymous_authorization(True, [{"subject": {"kind": "Group", "name": "system:unauthenticated"}, "rules": [{"verbs": ["*"], "resources": ["*"]}]}]))

        token = analyze_service_account_token_profile({"kind": "Pod", "metadata": {"name": "bad"}, "spec": {"automountServiceAccountToken": True, "volumes": [{"projected": {"sources": [{"serviceAccountToken": {"expirationSeconds": 60}}]}}]}} , rbac_rows=[])
        self.assertEqual("FAIL", token.status)
        self.assertFalse(token.expiration_ok)
        self.assertFalse(token.audience_ok)

    def test_missing_evidence_stays_unknown_and_identity_rows_redact_material(self) -> None:
        profile = analyze_authentication_profile()
        self.assertIsNone(profile.anonymous_auth)
        self.assertEqual("UNKNOWN", profile.status)
        self.assertEqual("UNKNOWN", analyze_oidc_authentication().status)
        self.assertEqual("UNKNOWN", analyze_webhook_authentication().status)
        self.assertEqual("UNKNOWN", analyze_front_proxy_authentication().status)
        token = analyze_service_account_token_profile({})
        self.assertEqual("UNKNOWN", token.status)
        self.assertIsNone(token.effective_automount)

        identities = analyze_identity_profiles([
            {"subject": {"kind": "User", "name": "alice"}, "rules": [{"verbs": ["get"], "resources": ["pods"]}], "token": "do-not-store"},
        ])
        self.assertEqual("User:alice", identities[0].subject)
        self.assertEqual("PASS", identities[0].status)
        self.assertNotIn("do-not-store", str(identities[0].to_dict()))


if __name__ == "__main__":
    unittest.main()
