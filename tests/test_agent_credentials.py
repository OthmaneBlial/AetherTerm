"""Credential-file permissions and device binding."""

from pathlib import Path
import os
import stat
import tempfile
import unittest

from client.main import read_token_file
from server.agents import AgentRegistry, issue_credential, revoke_device


class AgentCredentialTests(unittest.TestCase):
    def test_private_credential_rotation_and_rejection(self):
        with tempfile.TemporaryDirectory(prefix="aetherterm-agent-test-") as directory:
            base = Path(directory)
            registry_path = base / "agents.json"
            original_file = base / "original.token"
            issue_credential(registry_path, "linux-one", original_file, description="Build host")
            self.assertEqual(stat.S_IMODE(original_file.stat().st_mode), 0o600)
            token = read_token_file(original_file)
            registry = AgentRegistry(registry_path)
            self.assertIsNotNone(registry.authenticate("linux-one", token))
            self.assertIsNone(registry.authenticate("linux-two", token))
            self.assertEqual(registry.visible_devices(), [{"deviceId": "linux-one", "description": "Build host"}])

            os.chmod(registry_path, 0o644)
            self.assertIsNone(registry.authenticate("linux-one", token))
            self.assertEqual(registry.visible_devices(), [])
            os.chmod(registry_path, 0o600)
            saved_registry = base / "saved-agents.json"
            registry_path.rename(saved_registry)
            registry_path.symlink_to(saved_registry)
            self.assertIsNone(registry.authenticate("linux-one", token))
            registry_path.unlink()
            saved_registry.rename(registry_path)

            os.chmod(original_file, 0o644)
            with self.assertRaises(ValueError):
                read_token_file(original_file)
            os.chmod(original_file, 0o600)
            symlink = base / "link.token"
            symlink.symlink_to(original_file)
            with self.assertRaises(ValueError):
                read_token_file(symlink)

            rotated_file = base / "rotated.token"
            issue_credential(registry_path, "linux-one", rotated_file, rotate=True)
            self.assertEqual(registry.visible_devices()[0]["description"], "Build host")
            self.assertIsNone(registry.authenticate("linux-one", token))
            rotated = read_token_file(rotated_file)
            self.assertIsNotNone(registry.authenticate("linux-one", rotated))
            revoke_device(registry_path, "linux-one")
            self.assertIsNone(registry.authenticate("linux-one", rotated))
            self.assertEqual(registry.visible_devices(), [])
            with self.assertRaises(ValueError):
                issue_credential(registry_path, "bad-device", base / "bad.token", description="bad\nlabel")


if __name__ == "__main__":
    unittest.main()
