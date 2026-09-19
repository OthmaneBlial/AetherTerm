"""A private identity backup can be restored, with explicit stale-backup risk."""

from pathlib import Path
import os
import shutil
import tempfile
import unittest

from client.main import read_token_file
from server.agents import AgentRegistry, issue_credential
from server.auth import OperatorAuth, initialize_operator


class RecoveryTests(unittest.TestCase):
    def test_restore_private_identities_and_reject_old_browser_session(self):
        with tempfile.TemporaryDirectory(prefix="aetherterm-recovery-") as directory:
            root = Path(directory)
            state = root / "state"
            backup = root / "backup"
            state.mkdir(mode=0o700)
            backup.mkdir(mode=0o700)
            operator_path = state / "operator.json"
            registry_path = state / "agents.json"
            token_path = state / "agent.token"
            initialize_operator(operator_path, "recovery-test-password")
            issue_credential(registry_path, "recovery-agent", token_path)
            token = read_token_file(token_path)
            auth = OperatorAuth(operator_path)
            registry = AgentRegistry(registry_path)
            self.assertTrue(auth.verify_password("recovery-test-password"))
            self.assertIsNotNone(registry.authenticate("recovery-agent", token))
            browser_session = auth.create_session()
            self.assertIsNotNone(auth.session_key(browser_session))

            for source in (operator_path, registry_path, token_path):
                shutil.copy2(source, backup / source.name)
                self.assertEqual((backup / source.name).stat().st_mode & 0o777, 0o600)
                source.unlink()
            self.assertIsNone(auth.session_key(browser_session))
            self.assertIsNone(registry.authenticate("recovery-agent", token))

            for source in backup.iterdir():
                shutil.copy2(source, state / source.name)
                os.chmod(state / source.name, 0o600)
            self.assertTrue(auth.verify_password("recovery-test-password"))
            self.assertIsNone(auth.session_key(browser_session))
            self.assertEqual(read_token_file(token_path), token)
            self.assertIsNotNone(registry.authenticate("recovery-agent", token))

            rotated_file = state / "rotated.token"
            issue_credential(registry_path, "recovery-agent", rotated_file, rotate=True)
            rotated_token = read_token_file(rotated_file)
            self.assertIsNone(registry.authenticate("recovery-agent", token))
            self.assertIsNotNone(registry.authenticate("recovery-agent", rotated_token))
            shutil.copy2(backup / "agents.json", registry_path)
            self.assertIsNotNone(registry.authenticate("recovery-agent", token))
            self.assertIsNone(registry.authenticate("recovery-agent", rotated_token))


if __name__ == "__main__":
    unittest.main()
