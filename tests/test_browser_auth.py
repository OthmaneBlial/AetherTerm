"""Real HTTP/WebSocket regression tests for the browser shell boundary."""

import asyncio
import base64
import http.client
import json
import os
from pathlib import Path
import re
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

from server.agents import issue_credential, revoke_device
from server.auth import COOKIE_NAME, initialize_operator


ROOT = Path(__file__).resolve().parents[1]


class BrowserAuthTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="aetherterm-auth-test-")
        self.operator_file = Path(self.temp.name) / "operator.json"
        initialize_operator(self.operator_file, "a-test-password-only")
        self.agents_file = Path(self.temp.name) / "agents.json"
        token_file = Path(self.temp.name) / "agent.token"
        issue_credential(self.agents_file, "test-agent", token_file)
        self.token_file = token_file
        self.agent_token = token_file.read_text(encoding="utf-8").strip()
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            self.port = listener.getsockname()[1]
        env = {
            **os.environ, "AETHERTERM_OPERATOR_FILE": str(self.operator_file),
            "AETHERTERM_AGENTS_FILE": str(self.agents_file), "PYTHONDONTWRITEBYTECODE": "1", "PYTHONUNBUFFERED": "1",
        }
        self.server_env = env
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

    def start_real_agent(self):
        agent_log = open(Path(self.temp.name) / "agent.log", "w+", encoding="utf-8")
        agent = subprocess.Popen(
            [sys.executable, "client/main.py", "--host", "127.0.0.1", "--port", str(self.port),
             "--device-id", "test-agent", "--token-file", str(self.token_file)],
            cwd=ROOT, stdout=agent_log, stderr=subprocess.STDOUT, start_new_session=True,
            env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1", "PYTHONUNBUFFERED": "1"},
        )
        return agent, agent_log

    async def test_login_origin_and_cross_browser_session_ownership(self):
        origin = f"http://127.0.0.1:{self.port}"
        uri = f"ws://127.0.0.1:{self.port}/ws"
        status, login_headers = self.request("GET", "/login")
        self.assertEqual(status, 200)
        self.assertIn("script-src 'self'", login_headers["content-security-policy"])
        self.assertIn(f"connect-src 'self' ws://127.0.0.1:{self.port}",
                      login_headers["content-security-policy"])
        self.assertEqual(login_headers["x-frame-options"], "DENY")
        self.assertEqual(login_headers["referrer-policy"], "same-origin")
        self.assertEqual(self.request("GET", "/favicon.svg")[0], 200)
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
            await agent.send(json.dumps({"type": "register", "deviceId": "test-agent", "token": self.agent_token}))
            self.assertEqual(json.loads(await agent.recv())["type"], "registered")
            async with websockets.connect(uri, origin=origin, additional_headers={"Cookie": cookie}) as owner:
                await owner.send(json.dumps({"type": "list_devices"}))
                self.assertEqual(json.loads(await owner.recv())["devices"], ["test-agent"])
                await owner.send(json.dumps({"type": "start_session", "deviceId": "test-agent"}))
                started = json.loads(await owner.recv())
                self.assertEqual(started["type"], "session_started")
                self.assertEqual(json.loads(await agent.recv())["sessionId"], started["sessionId"])
                await agent.send(json.dumps({"type": "session_ready", "sessionId": started["sessionId"]}))
                self.assertEqual(json.loads(await owner.recv())["type"], "session_ready")

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

    async def test_device_identity_rotation_and_revocation(self):
        agent_uri = f"ws://127.0.0.1:{self.port}/client"
        origin = f"http://127.0.0.1:{self.port}"
        status, headers = self.request("POST", "/login", "password=a-test-password-only", {"Origin": origin})
        self.assertEqual(status, 303)
        cookie = headers["set-cookie"].split(";", 1)[0]

        async with websockets.connect(agent_uri) as wrong:
            await wrong.send(json.dumps({"type": "register", "deviceId": "other-agent", "token": self.agent_token}))
            self.assertEqual(json.loads(await wrong.recv())["message"], "Invalid device credential")
            with self.assertRaises(ConnectionClosed):
                await wrong.recv()

        async with websockets.connect(agent_uri) as agent_a:
            await agent_a.send(json.dumps({"type": "register", "deviceId": "test-agent", "token": self.agent_token}))
            self.assertEqual(json.loads(await agent_a.recv())["type"], "registered")
            async with websockets.connect(agent_uri) as duplicate:
                await duplicate.send(json.dumps({"type": "register", "deviceId": "test-agent", "token": self.agent_token}))
                self.assertEqual(json.loads(await duplicate.recv())["message"], "Device ID already in use")

            second_file = Path(self.temp.name) / "second.token"
            issue_credential(self.agents_file, "second-agent", second_file)
            second_token = second_file.read_text(encoding="utf-8").strip()
            async with websockets.connect(agent_uri) as agent_b:
                await agent_b.send(json.dumps({"type": "register", "deviceId": "second-agent", "token": second_token}))
                self.assertEqual(json.loads(await agent_b.recv())["type"], "registered")
                async with websockets.connect(f"ws://127.0.0.1:{self.port}/ws", origin=origin, additional_headers={"Cookie": cookie}) as browser:
                    await browser.send(json.dumps({"type": "list_devices"}))
                    self.assertEqual(set(json.loads(await browser.recv())["devices"]), {"test-agent", "second-agent"})
                    await browser.send(json.dumps({"type": "start_session", "deviceId": "second-agent"}))
                    session = json.loads(await browser.recv())["sessionId"]
                    self.assertEqual(json.loads(await agent_b.recv())["sessionId"], session)
                    await agent_b.send(json.dumps({"type": "session_ready", "sessionId": session}))
                    self.assertEqual(json.loads(await browser.recv())["type"], "session_ready")
                    await agent_a.send(json.dumps({"type": "term_data", "sessionId": session, "data": base64.b64encode(b"forged").decode()}))
                    await agent_b.send(json.dumps({"type": "term_data", "sessionId": session, "data": base64.b64encode(b"legitimate").decode()}))
                    output = json.loads(await asyncio.wait_for(browser.recv(), 2))
                    self.assertEqual(base64.b64decode(output["data"]), b"legitimate")

                rotated_file = Path(self.temp.name) / "rotated.token"
                issue_credential(self.agents_file, "test-agent", rotated_file, rotate=True)
                with self.assertRaises(ConnectionClosed):
                    await asyncio.wait_for(agent_a.recv(), 3)

        async with websockets.connect(agent_uri) as old_credential:
            await old_credential.send(json.dumps({"type": "register", "deviceId": "test-agent", "token": self.agent_token}))
            self.assertEqual(json.loads(await old_credential.recv())["message"], "Invalid device credential")

        new_token = rotated_file.read_text(encoding="utf-8").strip()
        async with websockets.connect(agent_uri) as rotated:
            await rotated.send(json.dumps({"type": "register", "deviceId": "test-agent", "token": new_token}))
            self.assertEqual(json.loads(await rotated.recv())["type"], "registered")
            revoke_device(self.agents_file, "test-agent")
            with self.assertRaises(ConnectionClosed):
                await asyncio.wait_for(rotated.recv(), 3)

        async with websockets.connect(agent_uri) as revoked:
            await revoked.send(json.dumps({"type": "register", "deviceId": "test-agent", "token": new_token}))
            self.assertEqual(json.loads(await revoked.recv())["message"], "Invalid device credential")
        self.server_log.flush()
        self.server_log.seek(0)
        logs = self.server_log.read()
        self.assertNotIn(self.agent_token, logs)
        self.assertNotIn(new_token, logs)
        self.assertNotIn(second_token, logs)

    async def test_malformed_frames_and_session_quota_do_not_break_other_sockets(self):
        origin = f"http://127.0.0.1:{self.port}"
        status, headers = self.request("POST", "/login", "password=a-test-password-only", {"Origin": origin})
        self.assertEqual(status, 303)
        cookie = headers["set-cookie"].split(";", 1)[0]
        browser_uri = f"ws://127.0.0.1:{self.port}/ws"
        agent_uri = f"ws://127.0.0.1:{self.port}/client"
        async with websockets.connect(agent_uri) as agent:
            await agent.send("not json")
            self.assertEqual(json.loads(await agent.recv())["message"], "Invalid JSON")
            await agent.send(json.dumps({"type": "register", "deviceId": "test-agent", "token": self.agent_token}))
            self.assertEqual(json.loads(await agent.recv())["type"], "registered")
            async with websockets.connect(browser_uri, origin=origin, additional_headers={"Cookie": cookie}) as browser:
                for invalid in ("not json", json.dumps({"type": []}), json.dumps({"type": "resize"})):
                    await browser.send(invalid)
                    self.assertEqual(json.loads(await browser.recv())["type"], "error")
                sessions = []
                for _ in range(4):
                    await browser.send(json.dumps({"type": "start_session", "deviceId": "test-agent"}))
                    started = json.loads(await browser.recv())
                    self.assertEqual(started["type"], "session_started")
                    sessions.append(started["sessionId"])
                    self.assertEqual(json.loads(await agent.recv())["sessionId"], sessions[-1])
                    await agent.send(json.dumps({"type": "session_ready", "sessionId": sessions[-1]}))
                    self.assertEqual(json.loads(await browser.recv())["type"], "session_ready")
                await browser.send(json.dumps({"type": "start_session", "deviceId": "test-agent"}))
                self.assertEqual(json.loads(await browser.recv())["message"], "Session limit reached")
                await browser.send(json.dumps({"type": "term_input", "sessionId": sessions[0], "input": "@@@"}))
                self.assertEqual(json.loads(await browser.recv())["message"], "Invalid terminal data")
                await browser.send(json.dumps({"type": "term_input", "sessionId": sessions[0],
                                               "input": base64.b64encode(b"works\n").decode()}))
                self.assertEqual(json.loads(await agent.recv())["sessionId"], sessions[0])
                await agent.send(json.dumps({"type": "term_data", "sessionId": sessions[0], "data": "bad!"}))
                self.assertEqual(json.loads(await agent.recv())["message"], "Invalid terminal data")
                await agent.send(json.dumps({"type": "term_data", "sessionId": sessions[0],
                                             "data": base64.b64encode(b"still works").decode()}))
                self.assertEqual(base64.b64decode(json.loads(await browser.recv())["data"]), b"still works")

    async def test_real_agent_sessions_are_isolated_and_closed(self):
        agent, agent_log = self.start_real_agent()
        origin = f"http://127.0.0.1:{self.port}"
        status, headers = self.request("POST", "/login", "password=a-test-password-only", {"Origin": origin})
        self.assertEqual(status, 303)
        cookie = headers["set-cookie"].split(";", 1)[0]
        uri = f"ws://127.0.0.1:{self.port}/ws"

        async def output_until(browser, pattern):
            output = ""
            for _ in range(40):
                message = json.loads(await asyncio.wait_for(browser.recv(), 2))
                if message["type"] == "term_data":
                    output += base64.b64decode(message["data"]).decode(errors="replace")
                if re.search(pattern, output):
                    return output
            self.fail(f"No {pattern} in terminal output")

        async def open_session(browser):
            await browser.send(json.dumps({"type": "start_session", "deviceId": "test-agent"}))
            started = json.loads(await asyncio.wait_for(browser.recv(), 3))
            self.assertEqual(started["type"], "session_started")
            ready = json.loads(await asyncio.wait_for(browser.recv(), 3))
            self.assertEqual(ready, {"type": "session_ready", "sessionId": started["sessionId"]})
            return started["sessionId"]

        try:
            async with websockets.connect(uri, origin=origin, additional_headers={"Cookie": cookie}) as first, \
                       websockets.connect(uri, origin=origin, additional_headers={"Cookie": cookie}) as second:
                for _ in range(40):
                    await first.send(json.dumps({"type": "list_devices"}))
                    if "test-agent" in json.loads(await first.recv())["devices"]:
                        break
                    await asyncio.sleep(0.1)
                else:
                    self.fail("Agent did not register")
                first_id = await open_session(first)
                second_id = await open_session(second)
                for browser, session_id, marker in ((first, first_id, "FIRST"), (second, second_id, "SECOND")):
                    command = f"printf '{marker}_%s\\n' \"$$\"\n".encode()
                    await browser.send(json.dumps({"type": "term_input", "sessionId": session_id,
                                                   "input": base64.b64encode(command).decode()}))
                first_output = await output_until(first, r"FIRST_\d+")
                second_output = await output_until(second, r"SECOND_\d+")
                first_pid = int(re.search(r"FIRST_(\d+)", first_output).group(1))
                second_pid = int(re.search(r"SECOND_(\d+)", second_output).group(1))
                self.assertNotEqual(first_pid, second_pid)
                self.assertNotIn("SECOND_", first_output)
                self.assertNotIn("FIRST_", second_output)
                split_unicode = b"printf '\\303'; sleep 0.2; printf '\\251\\n'\n"
                await first.send(json.dumps({"type": "term_input", "sessionId": first_id,
                                             "input": base64.b64encode(split_unicode).decode()}))
                received = b""
                chunks = []
                for _ in range(40):
                    message = json.loads(await asyncio.wait_for(first.recv(), 2))
                    if message["type"] == "term_data":
                        chunk = base64.b64decode(message["data"])
                        chunks.append(chunk)
                        received += chunk
                    if b"\xc3\xa9" in received:
                        break
                self.assertIn(b"\xc3\xa9", received)
                self.assertTrue(any(b"\xc3" in chunk and b"\xa9" not in chunk for chunk in chunks))
                await first.send(json.dumps({"type": "close_session", "sessionId": first_id}))
                self.assertEqual(json.loads(await first.recv())["type"], "session_closed")
                for _ in range(30):
                    try:
                        os.kill(first_pid, 0)
                    except ProcessLookupError:
                        break
                    await asyncio.sleep(0.1)
                else:
                    self.fail("Closed shell process remained alive")
                await second.send(json.dumps({"type": "term_input", "sessionId": second_id,
                                              "input": base64.b64encode(b"printf 'ALIVE\\n'\n").decode()}))
                self.assertIn("ALIVE", await output_until(second, r"ALIVE\r\n"))
                third_id = await open_session(first)
                await first.send(json.dumps({"type": "term_input", "sessionId": third_id,
                                             "input": base64.b64encode(b"printf 'THIRD_%s\\n' \"$$\"\n").decode()}))
                third_pid = int(re.search(r"THIRD_(\d+)", await output_until(first, r"THIRD_\d+")).group(1))
                await first.close()
                for _ in range(30):
                    try:
                        os.kill(third_pid, 0)
                    except ProcessLookupError:
                        break
                    await asyncio.sleep(0.1)
                else:
                    self.fail("Browser disconnect left a shell process alive")
                os.killpg(agent.pid, signal.SIGTERM)
                for _ in range(20):
                    message = json.loads(await asyncio.wait_for(second.recv(), 5))
                    if message["type"] == "session_closed":
                        self.assertEqual(message["sessionId"], second_id)
                        break
                else:
                    self.fail("No session_closed event after agent SIGTERM")
                await asyncio.to_thread(agent.wait, 5)
                for _ in range(30):
                    try:
                        os.kill(second_pid, 0)
                    except ProcessLookupError:
                        break
                    await asyncio.sleep(0.1)
                else:
                    self.fail("Shell process remained after agent SIGTERM")
        finally:
            if agent.poll() is None:
                os.killpg(agent.pid, signal.SIGKILL)
                agent.wait(timeout=5)
            agent_log.close()

    async def test_server_restart_closes_old_shell_and_agent_reconnects(self):
        agent, agent_log = self.start_real_agent()
        origin = f"http://127.0.0.1:{self.port}"
        uri = f"ws://127.0.0.1:{self.port}/ws"

        async def signed_in_browser():
            status, headers = self.request("POST", "/login", "password=a-test-password-only", {"Origin": origin})
            self.assertEqual(status, 303)
            return await websockets.connect(uri, origin=origin,
                                            additional_headers={"Cookie": headers["set-cookie"].split(";", 1)[0]})

        async def wait_for_agent(browser):
            for _ in range(100):
                await browser.send(json.dumps({"type": "list_devices"}))
                if "test-agent" in json.loads(await browser.recv())["devices"]:
                    return
                await asyncio.sleep(0.1)
            self.fail("Agent did not reconnect")

        try:
            async with await signed_in_browser() as browser:
                await wait_for_agent(browser)
                await browser.send(json.dumps({"type": "start_session", "deviceId": "test-agent"}))
                session_id = json.loads(await browser.recv())["sessionId"]
                self.assertEqual(json.loads(await browser.recv())["type"], "session_ready")
                command = b"printf 'OLD_PID_%s\\n' \"$$\"\n"
                await browser.send(json.dumps({"type": "term_input", "sessionId": session_id,
                                               "input": base64.b64encode(command).decode()}))
                output = b""
                for _ in range(40):
                    message = json.loads(await asyncio.wait_for(browser.recv(), 2))
                    if message["type"] == "term_data":
                        output += base64.b64decode(message["data"])
                    match = re.search(rb"OLD_PID_(\d+)", output)
                    if match:
                        old_pid = int(match.group(1))
                        break
                else:
                    self.fail("No first shell PID")
                os.killpg(self.server.pid, signal.SIGTERM)
                await asyncio.to_thread(self.server.wait, 5)
                with self.assertRaises(ConnectionClosed):
                    while True:
                        await asyncio.wait_for(browser.recv(), 5)
                for _ in range(40):
                    try:
                        os.kill(old_pid, 0)
                    except ProcessLookupError:
                        break
                    await asyncio.sleep(0.1)
                else:
                    self.fail("Old shell survived server shutdown")

            self.server = subprocess.Popen(
                [sys.executable, "-m", "uvicorn", "server.main:app", "--host", "127.0.0.1", "--port", str(self.port)],
                cwd=ROOT, env=self.server_env, stdout=self.server_log, stderr=subprocess.STDOUT, start_new_session=True,
            )
            for _ in range(100):
                try:
                    if self.request("GET", "/login")[0] == 200:
                        break
                except (OSError, http.client.HTTPException):
                    await asyncio.sleep(0.1)
            else:
                self.fail("Server did not restart")
            async with await signed_in_browser() as browser:
                await wait_for_agent(browser)
                await browser.send(json.dumps({"type": "start_session", "deviceId": "test-agent"}))
                restarted_id = json.loads(await browser.recv())["sessionId"]
                self.assertEqual(json.loads(await browser.recv())["type"], "session_ready")
                await browser.send(json.dumps({"type": "term_input", "sessionId": restarted_id,
                                               "input": base64.b64encode(b"printf 'RECONNECTED\\n'\n").decode()}))
                output = b""
                for _ in range(40):
                    message = json.loads(await asyncio.wait_for(browser.recv(), 2))
                    if message["type"] == "term_data":
                        output += base64.b64decode(message["data"])
                    if b"RECONNECTED\r\n" in output:
                        break
                else:
                    self.fail("No shell output after reconnect")
        finally:
            if agent.poll() is None:
                os.killpg(agent.pid, signal.SIGTERM)
                agent.wait(timeout=5)
            agent_log.close()

    async def test_unready_agent_session_times_out_and_frees_capacity(self):
        origin = f"http://127.0.0.1:{self.port}"
        status, headers = self.request("POST", "/login", "password=a-test-password-only", {"Origin": origin})
        self.assertEqual(status, 303)
        cookie = headers["set-cookie"].split(";", 1)[0]
        async with websockets.connect(f"ws://127.0.0.1:{self.port}/client") as agent:
            await agent.send(json.dumps({"type": "register", "deviceId": "test-agent", "token": self.agent_token}))
            self.assertEqual(json.loads(await agent.recv())["type"], "registered")
            async with websockets.connect(f"ws://127.0.0.1:{self.port}/ws", origin=origin,
                                          additional_headers={"Cookie": cookie}) as browser:
                await browser.send(json.dumps({"type": "start_session", "deviceId": "test-agent"}))
                session_id = json.loads(await browser.recv())["sessionId"]
                self.assertEqual(json.loads(await agent.recv())["sessionId"], session_id)
                closed = json.loads(await asyncio.wait_for(browser.recv(), 12))
                self.assertEqual(closed, {"type": "session_closed", "sessionId": session_id,
                                          "reason": "Shell did not become ready"})
                self.assertEqual(json.loads(await agent.recv()), {"type": "close_session", "sessionId": session_id})
                await browser.send(json.dumps({"type": "start_session", "deviceId": "test-agent"}))
                replacement = json.loads(await browser.recv())["sessionId"]
                self.assertNotEqual(replacement, session_id)
                self.assertEqual(json.loads(await agent.recv())["sessionId"], replacement)
                await agent.send(json.dumps({"type": "session_ready", "sessionId": replacement}))
                self.assertEqual(json.loads(await browser.recv()), {"type": "session_ready", "sessionId": replacement})

    async def test_enrolled_offline_metadata_never_exposes_credentials(self):
        second_file = Path(self.temp.name) / "second.token"
        issue_credential(self.agents_file, "second-agent", second_file, description="Build host")
        second_token = second_file.read_text(encoding="utf-8").strip()
        origin = f"http://127.0.0.1:{self.port}"
        status, headers = self.request("POST", "/login", "password=a-test-password-only", {"Origin": origin})
        self.assertEqual(status, 303)
        cookie = headers["set-cookie"].split(";", 1)[0]
        async with websockets.connect(f"ws://127.0.0.1:{self.port}/ws", origin=origin,
                                      additional_headers={"Cookie": cookie}) as browser:
            await browser.send(json.dumps({"type": "list_devices"}))
            listing = json.loads(await browser.recv())
            self.assertEqual(listing["devices"], [])
            self.assertEqual(listing["deviceDetails"][1], {"deviceId": "test-agent", "description": "",
                                                           "connected": False, "lastSeen": None})
            self.assertEqual(listing["deviceDetails"][0]["description"], "Build host")
            self.assertNotIn(self.agent_token, json.dumps(listing))
            self.assertNotIn(second_token, json.dumps(listing))
            async with websockets.connect(f"ws://127.0.0.1:{self.port}/client") as agent:
                await agent.send(json.dumps({"type": "register", "deviceId": "second-agent", "token": second_token}))
                self.assertEqual(json.loads(await agent.recv())["type"], "registered")
                await browser.send(json.dumps({"type": "list_devices"}))
                listing = json.loads(await browser.recv())
                self.assertEqual(listing["devices"], ["second-agent"])
                self.assertTrue(listing["deviceDetails"][0]["connected"])
                self.assertIsInstance(listing["deviceDetails"][0]["lastSeen"], float)
            await browser.send(json.dumps({"type": "list_devices"}))
            listing = json.loads(await browser.recv())
            self.assertFalse(listing["deviceDetails"][0]["connected"])
            self.assertIsInstance(listing["deviceDetails"][0]["lastSeen"], float)
            revoke_device(self.agents_file, "second-agent")
            await browser.send(json.dumps({"type": "list_devices"}))
            listing = json.loads(await browser.recv())
            self.assertEqual([device["deviceId"] for device in listing["deviceDetails"]], ["test-agent"])

    async def test_revoked_real_agent_stops_instead_of_retrying(self):
        agent, agent_log = self.start_real_agent()
        try:
            origin = f"http://127.0.0.1:{self.port}"
            status, headers = self.request("POST", "/login", "password=a-test-password-only", {"Origin": origin})
            self.assertEqual(status, 303)
            cookie = headers["set-cookie"].split(";", 1)[0]
            async with websockets.connect(f"ws://127.0.0.1:{self.port}/ws", origin=origin,
                                          additional_headers={"Cookie": cookie}) as browser:
                for _ in range(100):
                    await browser.send(json.dumps({"type": "list_devices"}))
                    if "test-agent" in json.loads(await browser.recv())["devices"]:
                        break
                    await asyncio.sleep(0.1)
                else:
                    self.fail("Agent did not register")
                revoke_device(self.agents_file, "test-agent")
                self.assertEqual(await asyncio.to_thread(agent.wait, 5), 0)
                await browser.send(json.dumps({"type": "list_devices"}))
                self.assertEqual(json.loads(await browser.recv())["devices"], [])
        finally:
            if agent.poll() is None:
                os.killpg(agent.pid, signal.SIGKILL)
                agent.wait(timeout=5)
            agent_log.close()


if __name__ == "__main__":
    unittest.main()
