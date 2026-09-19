"""Linux CI smoke test: non-root container server, host agent, authorized PTY."""

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
import uuid

import websockets

from server.agents import issue_credential
from server.auth import COOKIE_NAME, initialize_operator
from server.protocol import WEBSOCKET_SUBPROTOCOL


def stop(process):
    if process is None or process.poll() is not None:
        return
    os.killpg(process.pid, signal.SIGTERM)
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        os.killpg(process.pid, signal.SIGKILL)
        process.wait(timeout=5)


def request(port, method, path, *, body=None, headers=None):
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=3)
    connection.request(method, path, body=body, headers=headers or {})
    response = connection.getresponse()
    result = response.status, dict(response.getheaders())
    response.read()
    connection.close()
    return result


async def main():
    image = os.environ.get("AETHERTERM_CONTAINER_IMAGE", "aetherterm:ci")
    configured_user = subprocess.check_output(
        ["docker", "image", "inspect", image, "--format", "{{.Config.User}}"], text=True
    ).strip()
    if configured_user in ("", "0", "root"):
        raise AssertionError(f"Container image runs as root: {configured_user!r}")
    with tempfile.TemporaryDirectory(prefix="aetherterm-container-") as temporary:
        root = Path(temporary)
        state = root / "state"
        state.mkdir(mode=0o700)
        token_file = root / "agent.token"
        initialize_operator(state / "operator.json", "temporary-container-password")
        issue_credential(state / "agents.json", "container-agent", token_file)
        subprocess.run(["sudo", "chown", "-R", "10001:10001", str(state)], check=True)
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            port = listener.getsockname()[1]
        container_name = f"aetherterm-smoke-{uuid.uuid4().hex[:12]}"
        container_log = (root / "container.log").open("w+", encoding="utf-8")
        agent_log = (root / "agent.log").open("w+", encoding="utf-8")
        container = agent = None
        try:
            container = subprocess.Popen(
                ["docker", "run", "--rm", "--name", container_name, "--network", "host", "--read-only",
                 "--tmpfs", "/tmp:rw,nosuid,nodev,size=16m", "--cap-drop", "ALL",
                 "--security-opt", "no-new-privileges", "--mount", f"type=bind,src={state},dst=/data",
                 image, "--port", str(port)], stdout=container_log, stderr=subprocess.STDOUT,
                start_new_session=True,
            )
            for _ in range(100):
                try:
                    if request(port, "GET", "/login")[0] == 200:
                        break
                except OSError:
                    await asyncio.sleep(0.1)
                if container.poll() is not None:
                    raise AssertionError("Container exited before readiness")
            else:
                raise AssertionError("Container did not start")
            agent = subprocess.Popen(
                [sys.executable, "-m", "client.main", "--host", "127.0.0.1", "--port", str(port),
                 "--device-id", "container-agent", "--token-file", str(token_file)],
                stdout=agent_log, stderr=subprocess.STDOUT, start_new_session=True,
                env={**os.environ, "PYTHONUNBUFFERED": "1"},
            )
            origin = f"http://127.0.0.1:{port}"
            status, headers = request(port, "POST", "/login", body="password=temporary-container-password",
                                      headers={"Origin": origin})
            if status != 303:
                raise AssertionError(f"Container login returned {status}")
            cookie = headers["set-cookie"].split(";", 1)[0]
            if not cookie.startswith(COOKIE_NAME + "="):
                raise AssertionError("Operator cookie missing")
            async with websockets.connect(f"ws://127.0.0.1:{port}/ws", origin=origin,
                                          additional_headers={"Cookie": cookie},
                                          subprotocols=[WEBSOCKET_SUBPROTOCOL]) as browser:
                for _ in range(100):
                    await browser.send(json.dumps({"type": "list_devices"}))
                    listing = json.loads(await asyncio.wait_for(browser.recv(), 2))
                    if "container-agent" in listing["devices"]:
                        break
                    await asyncio.sleep(0.1)
                else:
                    raise AssertionError("Agent did not register through container server")
                await browser.send(json.dumps({"type": "start_session", "deviceId": "container-agent"}))
                started = json.loads(await asyncio.wait_for(browser.recv(), 3))
                if started["type"] != "session_started":
                    raise AssertionError(started)
                session_id = started["sessionId"]
                ready = json.loads(await asyncio.wait_for(browser.recv(), 3))
                if ready["type"] != "session_ready" or ready["sessionId"] != session_id:
                    raise AssertionError(ready)
                command = base64.b64encode(b"printf 'CONTAINER_OK\\n'\n").decode("ascii")
                await browser.send(json.dumps({"type": "term_input", "sessionId": session_id, "input": command}))
                output = b""
                for _ in range(40):
                    message = json.loads(await asyncio.wait_for(browser.recv(), 2))
                    if message["type"] == "term_data":
                        output += base64.b64decode(message["data"])
                    if b"CONTAINER_OK\r\n" in output:
                        break
                else:
                    raise AssertionError(f"Container PTY output missing: {output!r}")
        except BaseException:
            container_log.flush()
            agent_log.flush()
            print((root / "container.log").read_text(encoding="utf-8"), file=sys.stderr)
            print((root / "agent.log").read_text(encoding="utf-8"), file=sys.stderr)
            raise
        finally:
            stop(agent)
            if container is not None:
                subprocess.run(["docker", "stop", "--time", "5", container_name],
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
                stop(container)
            subprocess.run(["sudo", "chown", "-R", f"{os.getuid()}:{os.getgid()}", str(state)],
                           check=True)
            container_log.close()
            agent_log.close()
    print("Non-root container server, installed agent and real PTY: PASS")


if __name__ == "__main__":
    asyncio.run(main())
