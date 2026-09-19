"""Reject bad agent settings before a process tries to connect."""

from pathlib import Path
import unittest

from client.config import AgentConfig


class AgentConfigTests(unittest.TestCase):
    def test_invalid_settings_fail_before_network_access(self):
        base = AgentConfig("127.0.0.1", 8001, "agent-one", Path("unused.token"))
        base.validate()
        for config, message in (
            (AgentConfig("example.com", 8001, "agent-one", base.token_file), "Remote agents require"),
            (AgentConfig("127.0.0.1", 0, "agent-one", base.token_file), "host or port"),
            (AgentConfig("127.0.0.1", 8001, "bad/id", base.token_file), "Device ID"),
            (AgentConfig("127.0.0.1", 8001, "agent-one", base.token_file, "bad\nlabel"), "Description"),
            (AgentConfig("127.0.0.1", 8001, "agent-one", base.token_file,
                         ca_file=Path("missing.pem")), "--ca-file requires"),
            (AgentConfig("127.0.0.1", 8001, "agent-one", base.token_file,
                         tls=True, ca_file=Path("missing.pem")), "CA file not found"),
        ):
            with self.subTest(config=config), self.assertRaisesRegex(ValueError, message):
                config.validate()


if __name__ == "__main__":
    unittest.main()
