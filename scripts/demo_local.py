"""Run a disposable loopback server and agent for a real first-shell demo."""

import argparse
import asyncio
import http.client
import json
import os
from pathlib import Path
import secrets
import signal
import socket
import subprocess
import sys
import tempfile
import time
from urllib.parse import urlencode

import websockets

from server.agents import issue_credential
from server.auth import initialize_operator
from server.protocol import WEBSOCKET_SUBPROTOCOL


ROOT = Path(__file__).resolve().parents[1]


def stop(process: subprocess.Popen | None) -> None:
    if process is None or process.poll() is not None:
        return
    os.killpg(process.pid, signal.SIGTERM)
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        os.killpg(process.pid, signal.SIGKILL)
        process.wait(timeout=5)


def request(port: int, method: str, path: str, body: str | None = None, headers: dict | None = None):
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=2)
    try:
        connection.request(method, path, body=body, headers=headers or {})
        response = connection.getresponse()
        result = response.status, dict(response.getheaders())
        response.read()
        return result
    finally:
        connection.close()


async def wait_for_agent(port: int, password: str) -> None:
    origin = f"http://127.0.0.1:{port}"
    status, headers = request(port, "POST", "/login", urlencode({"password": password}), {"Origin": origin})
    if status != 303:
        raise RuntimeError(f"Disposable operator sign-in failed: HTTP {status}")
    cookie = headers["set-cookie"].split(";", 1)[0]
    async with websockets.connect(f"ws://127.0.0.1:{port}/ws", origin=origin,
                                  additional_headers={"Cookie": cookie},
                                  subprotocols=[WEBSOCKET_SUBPROTOCOL]) as browser:
        for _ in range(100):
            await browser.send(json.dumps({"type": "list_devices"}))
            listing = json.loads(await asyncio.wait_for(browser.recv(), timeout=2))
            if "demo-agent" in listing["devices"]:
                return
            await asyncio.sleep(0.1)
    raise RuntimeError("Disposable agent did not register")


def main() -> None:
    parser = argparse.ArgumentParser(description="Run a disposable local AetherTerm demo")
    parser.add_argument("--check", action="store_true", help="Check startup and cleanup, then exit")
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="aetherterm-local-demo-") as temporary:
        directory = Path(temporary)
        password = secrets.token_urlsafe(24)
        operator = directory / "operator.json"
        agents = directory / "agents.json"
        token_file = directory / "demo-agent.token"
        initialize_operator(operator, password)
        issue_credential(agents, "demo-agent", token_file, description="Disposable local shell")
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            port = listener.getsockname()[1]
        environment = {**os.environ, "AETHERTERM_OPERATOR_FILE": str(operator),
                       "AETHERTERM_AGENTS_FILE": str(agents), "PYTHONUNBUFFERED": "1"}
        server_log = (directory / "server.log").open("w+", encoding="utf-8")
        agent_log = (directory / "agent.log").open("w+", encoding="utf-8")
        server = agent = None
        try:
            server = subprocess.Popen([sys.executable, "-m", "server.cli", "--port", str(port)],
                                      cwd=ROOT, env=environment, stdout=server_log,
                                      stderr=subprocess.STDOUT, start_new_session=True)
            for _ in range(100):
                try:
                    if request(port, "GET", "/login")[0] == 200:
                        break
                except OSError:
                    time.sleep(0.1)
                if server.poll() is not None:
                    raise RuntimeError("Disposable server exited during startup")
            else:
                raise RuntimeError("Disposable server did not start")
            agent = subprocess.Popen([sys.executable, "-m", "client.main", "--host", "127.0.0.1",
                                      "--port", str(port), "--device-id", "demo-agent",
                                      "--token-file", str(token_file)], cwd=ROOT, env=environment,
                                     stdout=agent_log, stderr=subprocess.STDOUT, start_new_session=True)
            asyncio.run(wait_for_agent(port, password))
            if args.check:
                print("Disposable loopback server and agent startup: PASS")
            else:
                print(f"Open http://127.0.0.1:{port}/web/", flush=True)
                print(f"Temporary operator password: {password}", flush=True)
                print("Select demo-agent for a real shell. Press Ctrl+C here to delete the demo identities.",
                      flush=True)
                while server.poll() is None and agent.poll() is None:
                    time.sleep(0.5)
                raise RuntimeError("Demo server or agent stopped unexpectedly")
        except KeyboardInterrupt:
            pass
        except BaseException:
            server_log.flush()
            agent_log.flush()
            print((directory / "server.log").read_text(encoding="utf-8"), file=sys.stderr)
            print((directory / "agent.log").read_text(encoding="utf-8"), file=sys.stderr)
            raise
        finally:
            stop(agent)
            stop(server)
            server_log.close()
            agent_log.close()


if __name__ == "__main__":
    main()
