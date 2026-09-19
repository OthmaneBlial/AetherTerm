"""Remote cleartext is refused before shell credentials can travel."""

import unittest

from client.main import server_uri
from server.network import transport_allowed


class TransportPolicyTests(unittest.TestCase):
    def test_remote_cleartext_denied_and_loopback_allowed(self):
        self.assertTrue(transport_allowed("http", "127.0.0.1"))
        self.assertTrue(transport_allowed("ws", "::1"))
        self.assertFalse(transport_allowed("http", "192.0.2.10"))
        self.assertFalse(transport_allowed("ws", "192.0.2.10"))
        self.assertTrue(transport_allowed("https", "192.0.2.10"))
        self.assertTrue(transport_allowed("wss", "192.0.2.10"))
        self.assertEqual(server_uri("127.0.0.1", 8001, False), "ws://127.0.0.1:8001/client")
        self.assertEqual(server_uri("::1", 8001, False), "ws://[::1]:8001/client")
        self.assertEqual(server_uri("example.test", 443, True), "wss://example.test:443/client")
        with self.assertRaises(ValueError):
            server_uri("example.test", 80, False)
        with self.assertRaises(ValueError):
            server_uri("127.0.0.1", 0, False)


if __name__ == "__main__":
    unittest.main()
