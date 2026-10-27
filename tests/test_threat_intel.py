import unittest
from unittest.mock import patch
from cyberguard_threat_intel import inspect_target, investigate, dns_check

class ThreatIntelTests(unittest.TestCase):
    def test_blocks_private_ips(self):
        for url in ["http://127.0.0.1", "http://192.168.1.1", "http://[::1]/", "file:///etc/passwd", "http://user:pass@example.com"]:
            with self.assertRaises(ValueError): inspect_target(url)
    def test_no_network_by_default(self):
        with patch("socket.getaddrinfo", side_effect=AssertionError("network call")):
            result = investigate("https://www.python.org/")
        self.assertEqual(result["dns"]["status"], "disabled")
        self.assertEqual(result["virustotal"]["status"], "disabled")
    def test_dns_blocks_mixed_resolution(self):
        with patch("cyberguard_threat_intel.public_addresses", side_effect=ValueError("private address")):
            self.assertEqual(dns_check("https://www.python.org", enabled=True)["status"], "error")

if __name__ == "__main__": unittest.main()
