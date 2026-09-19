"""Multiple app instances must not share shell or authentication state."""

from pathlib import Path
import tempfile
import unittest

from server.auth import initialize_operator
from server.main import create_app


class ServerFactoryTests(unittest.TestCase):
    def test_instances_isolate_operator_sessions_and_devices(self):
        with tempfile.TemporaryDirectory(prefix="aetherterm-factory-") as directory:
            root = Path(directory)
            first_operator = root / "first.json"
            second_operator = root / "second.json"
            initialize_operator(first_operator, "first-test-password")
            initialize_operator(second_operator, "second-test-password")
            first = create_app(operator_path=first_operator, agents_path=root / "first-agents.json")
            second = create_app(operator_path=second_operator, agents_path=root / "second-agents.json")
            first_state = first.state.runtime
            second_state = second.state.runtime
            token = first_state.operator_auth.create_session()
            self.assertIsNotNone(first_state.operator_auth.session_key(token))
            self.assertIsNone(second_state.operator_auth.session_key(token))
            first_state.device_last_seen["first-only"] = 1.0
            self.assertEqual(second_state.device_last_seen, {})
            self.assertIsNot(first_state.browser_connections, second_state.browser_connections)


if __name__ == "__main__":
    unittest.main()
