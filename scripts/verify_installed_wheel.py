"""Exercise a wheel-installed server, agent and bundled UI outside the checkout."""

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

import websockets

from server.auth import initialize_operator


def request(port, method, path, *, body=None, headers=None):
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=3)
    connection.request(method, path, body=body, headers=headers or {})
    response = connection.getresponse()
    result = response.status, {name.lower(): value for name, value in response.getheaders()}, response.read()
    connection.close()
    return result


def stop(process):
    if process is None or process.poll() is not None:
        return
    os.killpg(process.pid, signal.SIGTERM)
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        os.killpg(process.pid, signal.SIGKILL)
        process.wait(timeout=5)
        raise AssertionError(f"Process {process.pid} did not stop after SIGTERM")


async def exercise(port, cookie):
    origin = f"http://127.0.0.1:{port}"
    async with websockets.connect(f"ws://127.0.0.1:{port}/ws", origin=origin,
                                  additional_headers={"Cookie": cookie}) as browser:
        for _ in range(100):
            await browser.send(json.dumps({"type": "list_devices"}))
            listing = json.loads(await asyncio.wait_for(browser.recv(), 2))
            if "wheel-agent" in listing["devices"]:
                break
            await asyncio.sleep(0.1)
        else:
            raise AssertionError("Installed agent never appeared")
        await browser.send(json.dumps({"type": "start_session", "deviceId": "wheel-agent"}))
        started = json.loads(await asyncio.wait_for(browser.recv(), 3))
        assert started["type"] == "session_started", started
        session_id = started["sessionId"]
        ready = json.loads(await asyncio.wait_for(browser.recv(), 3))
        assert ready == {"type": "session_ready", "sessionId": session_id}, ready
        command = base64.b64encode(b"printf 'WHEEL_OK\\n'\n").decode("ascii")
        await browser.send(json.dumps({"type": "term_input", "sessionId": session_id, "input": command}))
        output = b""
        for _ in range(40):
            message = json.loads(await asyncio.wait_for(browser.recv(), 2))
            if message["type"] == "term_data":
                output += base64.b64decode(message["data"])
            if b"WHEEL_OK\r\n" in output:
                break
        else:
            raise AssertionError(f"Installed PTY produced no expected output: {output!r}")
        await browser.send(json.dumps({"type": "close_session", "sessionId": session_id}))
        closed = json.loads(await asyncio.wait_for(browser.recv(), 3))
        assert closed["type"] == "session_closed", closed


def main():
    package_root = Path(__import__("server").__file__).resolve().parent
    repo_root = Path(__file__).resolve().parents[1]
    if repo_root in package_root.parents:
        raise AssertionError("Imported server from the checkout instead of the installed wheel")
    executable_dir = Path(sys.prefix) / "bin"
    with tempfile.TemporaryDirectory(prefix="aetherterm-wheel-smoke-") as temporary:
        directory = Path(temporary)
        operator = directory / "operator.json"
        agents = directory / "agents.json"
        credential = directory / "wheel-agent.token"
        initialize_operator(operator, "temporary-wheel-password")
        environment = {**os.environ, "AETHERTERM_OPERATOR_FILE": str(operator),
                       "AETHERTERM_AGENTS_FILE": str(agents), "PYTHONUNBUFFERED": "1"}
        subprocess.run([str(executable_dir / "aetherterm-admin"), "enroll", "wheel-agent",
                        "--output", str(credential)], cwd=directory, env=environment,
                       check=True, capture_output=True, text=True)
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            port = listener.getsockname()[1]
        server_log = (directory / "server.log").open("w+", encoding="utf-8")
        agent_log = (directory / "agent.log").open("w+", encoding="utf-8")
        server = agent = None
        try:
            server = subprocess.Popen([str(executable_dir / "aetherterm-server"), "--port", str(port)],
                                      cwd=directory, env=environment, stdout=server_log,
                                      stderr=subprocess.STDOUT, start_new_session=True)
            for _ in range(100):
                try:
                    if request(port, "GET", "/login")[0] == 200:
                        break
                except OSError:
                    time.sleep(0.1)
            else:
                raise AssertionError("Installed server did not start")
            agent = subprocess.Popen([str(executable_dir / "aetherterm-agent"), "--host", "127.0.0.1",
                                      "--port", str(port), "--device-id", "wheel-agent",
                                      "--token-file", str(credential)], cwd=directory, env=environment,
                                     stdout=agent_log, stderr=subprocess.STDOUT, start_new_session=True)
            origin = f"http://127.0.0.1:{port}"
            status, headers, _ = request(port, "POST", "/login", body="password=temporary-wheel-password",
                                         headers={"Origin": origin})
            assert status == 303, status
            cookie = headers["set-cookie"].split(";", 1)[0]
            status, _, page = request(port, "GET", "/web/", headers={"Cookie": cookie})
            assert status == 200 and b"assets/app.js" in page, status
            status, _, script = request(port, "GET", "/web/assets/app.js", headers={"Cookie": cookie})
            assert status == 200 and len(script) > 100_000, (status, len(script))
            asyncio.run(exercise(port, cookie))
        except BaseException:
            server_log.flush()
            agent_log.flush()
            print((directory / "server.log").read_text(encoding="utf-8"), file=sys.stderr)
            print((directory / "agent.log").read_text(encoding="utf-8"), file=sys.stderr)
            raise
        finally:
            try:
                stop(agent)
            finally:
                stop(server)
                server_log.close()
                agent_log.close()
    print("Installed wheel UI, operator sign-in, agent and real PTY: PASS")


if __name__ == "__main__":
    main()
