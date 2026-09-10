import unittest

from cloudnative_security.etcd_profile import (
    assess_cluster_consistency,
    parse_apiserver_etcd_client,
    parse_etcd_flags,
)


class EtcdProfileTests(unittest.TestCase):
    def test_secure_listeners_and_apiserver_client(self):
        profile = parse_etcd_flags(
            "--listen-client-urls=https://10.0.0.1:2379 "
            "--listen-peer-urls=https://10.0.0.1:2380 "
            "--client-cert-auth=true --peer-client-cert-auth=true"
        )
        self.assertEqual("PASS", profile.status)
        self.assertTrue(profile.client_tls)
        api = parse_apiserver_etcd_client(
            ["--etcd-servers=https://10.0.0.1:2379", "--etcd-cafile=/ca", "--etcd-certfile=/cert", "--etcd-keyfile=/key"]
        )
        self.assertEqual("PASS", api.status)
        self.assertTrue(api.tls)

    def test_cluster_consistency_ignores_per_node_ips(self):
        one = parse_etcd_flags({"listen-client-urls": "https://10.0.0.1:2379", "listen-peer-urls": "https://10.0.0.1:2380"})
        two = parse_etcd_flags({"listen-client-urls": "https://10.0.0.2:2379", "listen-peer-urls": "https://10.0.0.2:2380"})
        self.assertEqual("PASS", assess_cluster_consistency([one, two]).status)


if __name__ == "__main__":
    unittest.main()
