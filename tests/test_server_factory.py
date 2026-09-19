"""Multiple app instances must not share shell or authentication state."""

from pathlib import Path
from contextlib import redirect_stdout
from io import StringIO
import json
import os
import tempfile
import unittest

from server.auth import MAX_OPERATOR_SESSIONS, OperatorAuth, initialize_operator
from server.main import create_app, log_security_event


class ServerFactoryTests(unittest.TestCase):
    def test_operator_file_must_remain_private_and_regular(self):
        with tempfile.TemporaryDirectory(prefix="aetherterm-operator-file-") as directory:
            path = Path(directory) / "operator.json"
            initialize_operator(path, "private-test-password")
            auth = OperatorAuth(path)
            self.assertTrue(auth.verify_password("private-test-password"))
            os.chmod(path, 0o644)
            self.assertFalse(auth.verify_password("private-test-password"))
            os.chmod(path, 0o600)
            saved = Path(directory) / "saved-operator.json"
            path.rename(saved)
            path.symlink_to(saved)
            self.assertFalse(auth.verify_password("private-test-password"))
            path.unlink()
            saved.rename(path)
            self.assertTrue(auth.verify_password("private-test-password"))

    def test_operator_sessions_expire_and_remain_bounded(self):
        with tempfile.TemporaryDirectory(prefix="aetherterm-operator-") as directory:
            operator_file = Path(directory) / "operator.json"
            initialize_operator(operator_file, "bounded-test-password")
            auth = OperatorAuth(operator_file)
            first = auth.create_session()
            for _ in range(MAX_OPERATOR_SESSIONS):
                latest = auth.create_session()
            self.assertEqual(len(auth.sessions), MAX_OPERATOR_SESSIONS)
            self.assertIsNone(auth.session_key(first))
            self.assertIsNotNone(auth.session_key(latest))

    def test_audit_log_redacts_unexpected_detail(self):
        output = StringIO()
        with redirect_stdout(output):
            log_security_event("CLIENT_ERROR", "127.0.0.1", "token=private\nvalue")
        record = json.loads(output.getvalue())
        self.assertEqual(record["event"], "CLIENT_ERROR")
        self.assertEqual(record["clientIp"], "127.0.0.1")
        self.assertEqual(record["details"], "redacted")
        self.assertNotIn("private", output.getvalue())

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
