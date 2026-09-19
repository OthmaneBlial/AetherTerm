"""Real HTTP/WebSocket regression tests for the browser shell boundary."""

import asyncio
import base64
import http.client
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import sys
import tempfile
import time
import unittest
import urllib.request

import websockets
from websockets.exceptions import ConnectionClosed, InvalidStatus

from server.auth import COOKIE_NAME, initialize_operator


ROOT = Path(__file__).resolve().parents[1]


class BrowserAuthTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="aetherterm-auth-test-")
        self.operator_file = Path(self.temp.name) / "operator.json"
        initialize_operator(self.operator_file, "a-test-password-only")
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            self.port = listener.getsockname()[1]
        env = {**os.environ, "AETHERTERM_OPERATOR_FILE": str(self.operator_file), "PYTHONDONTWRITEBYTECODE": "1"}
        self.server_log = open(Path(self.temp.name) / "server.log", "w+", encoding="utf-8")
        self.server = subprocess.Popen(
            [sys.executable, "-m", "uvicorn", "server.main:app", "--host", "127.0.0.1", "--port", str(self.port)],
            cwd=ROOT, env=env, stdout=self.server_log, stderr=subprocess.STDOUT, start_new_session=True,
        )
        for _ in range(150):
            try:
                with urllib.request.urlopen(f"http://127.0.0.1:{self.port}/login", timeout=0.2) as response:
                    if response.status == 200:
                        break
            except Exception:
                time.sleep(0.1)
            if self.server.poll() is not None:
                self.server_log.seek(0)
                self.fail(f"Server exited:\n{self.server_log.read()}")
        else:
            self.server_log.seek(0)
            self.fail(f"Server did not start:\n{self.server_log.read()}")

    def tearDown(self):
        try:
            os.killpg(self.server.pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
        try:
            self.server.wait(timeout=5)
        except subprocess.TimeoutExpired:
            os.killpg(self.server.pid, signal.SIGKILL)
            self.server.wait(timeout=5)
        self.server_log.close()
        self.temp.cleanup()

    def request(self, method, path, body=None, headers=None):
        connection = http.client.HTTPConnection("127.0.0.1", self.port, timeout=3)
        connection.request(method, path, body=body, headers=headers or {})
        response = connection.getresponse()
        status, received_headers = response.status, {name.lower(): value for name, value in response.getheaders()}
        response.read()
        connection.close()
        return status, received_headers

    async def test_login_origin_and_cross_browser_session_ownership(self):
        origin = f"http://127.0.0.1:{self.port}"
        uri = f"ws://127.0.0.1:{self.port}/ws"
        status, _ = self.request("GET", "/web/")
        self.assertEqual(status, 303)
        with self.assertRaises(InvalidStatus):
            async with websockets.connect(uri, origin=origin):
                pass

        status, _ = self.request("POST", "/login", "password=a-test-password-only", {"Origin": "http://wrong.example"})
        self.assertEqual(status, 403)
        status, _ = self.request("POST", "/login", "password=wrong", {"Origin": origin})
        self.assertEqual(status, 401)
        status, headers = self.request("POST", "/login", "password=a-test-password-only", {"Origin": origin})
        self.assertEqual(status, 303)
        cookie = headers["set-cookie"].split(";", 1)[0]
        self.assertTrue(cookie.startswith(f"{COOKIE_NAME}="))
        self.assertIn("httponly", headers["set-cookie"].lower())
        self.assertEqual(self.request("GET", "/web/", headers={"Cookie": cookie})[0], 200)
        with self.assertRaises(InvalidStatus):
            async with websockets.connect(uri, origin="http://wrong.example", additional_headers={"Cookie": cookie}):
                pass

        async with websockets.connect(f"ws://127.0.0.1:{self.port}/client") as agent:
            await agent.send(json.dumps({"type": "register", "deviceId": "test-agent", "token": "secret123"}))
            self.assertEqual(json.loads(await agent.recv())["type"], "registered")
            async with websockets.connect(uri, origin=origin, additional_headers={"Cookie": cookie}) as owner:
                await owner.send(json.dumps({"type": "list_devices"}))
                self.assertEqual(json.loads(await owner.recv())["devices"], ["test-agent"])
                await owner.send(json.dumps({"type": "start_session", "deviceId": "test-agent"}))
                started = json.loads(await owner.recv())
                self.assertEqual(started["type"], "session_started")
                self.assertEqual(json.loads(await agent.recv())["sessionId"], started["sessionId"])

                async with websockets.connect(uri, origin=origin, additional_headers={"Cookie": cookie}) as other:
                    intruder_data = base64.b64encode(b"intruder\n").decode()
                    await other.send(json.dumps({"type": "term_input", "sessionId": started["sessionId"], "input": intruder_data}))
                    self.assertEqual(json.loads(await other.recv())["message"], "Session unavailable")
                    await other.send(json.dumps({"type": "resize", "sessionId": started["sessionId"], "cols": 100, "rows": 30}))
                    self.assertEqual(json.loads(await other.recv())["message"], "Session unavailable")

                    owner_data = base64.b64encode(b"owner\n").decode()
                    await owner.send(json.dumps({"type": "term_input", "sessionId": started["sessionId"], "input": owner_data}))
                    forwarded = json.loads(await asyncio.wait_for(agent.recv(), 2))
                    self.assertEqual(forwarded["data"], owner_data)
                    self.assertEqual(forwarded["sessionId"], started["sessionId"])

                status, _ = self.request("POST", "/logout", headers={"Origin": origin, "Cookie": cookie})
                self.assertEqual(status, 303)
                with self.assertRaises(ConnectionClosed):
                    await asyncio.wait_for(owner.recv(), 2)
        self.assertEqual(self.request("GET", "/web/", headers={"Cookie": cookie})[0], 303)

    async def test_operator_credential_change_revokes_live_browser(self):
        origin = f"http://127.0.0.1:{self.port}"
        status, headers = self.request("POST", "/login", "password=a-test-password-only", {"Origin": origin})
        self.assertEqual(status, 303)
        cookie = headers["set-cookie"].split(";", 1)[0]
        uri = f"ws://127.0.0.1:{self.port}/ws"
        async with websockets.connect(uri, origin=origin, additional_headers={"Cookie": cookie}) as browser:
            replacement = Path(self.temp.name) / "new-operator.json"
            initialize_operator(replacement, "new-test-password-only")
            os.replace(replacement, self.operator_file)
            with self.assertRaises(ConnectionClosed):
                await asyncio.wait_for(browser.recv(), 3)
        self.assertEqual(self.request("GET", "/web/", headers={"Cookie": cookie})[0], 303)
        self.assertEqual(self.request("POST", "/login", "password=a-test-password-only", {"Origin": origin})[0], 401)
        self.assertEqual(self.request("POST", "/login", "password=new-test-password-only", {"Origin": origin})[0], 303)


if __name__ == "__main__":
    unittest.main()
