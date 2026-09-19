"""Exercise a real Caddy TLS proxy, browser WebSocket, agent and PTY on loopback.

Run from a virtual environment with project dependencies installed:
    python scripts/verify_tls_proxy.py --caddy /path/to/caddy

This proves a local proxy configuration, not public DNS or another physical host.
"""

import argparse
import asyncio
import base64
from functools import partial
import http.client
import json
import os
from pathlib import Path
import signal
import socket
import ssl
import subprocess
import sys
import tempfile
import time
import urllib.request

import websockets


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from server.agents import issue_credential  # noqa: E402
from server.auth import initialize_operator  # noqa: E402
from server.protocol import WEBSOCKET_SUBPROTOCOL  # noqa: E402

connect = partial(websockets.connect, subprotocols=[WEBSOCKET_SUBPROTOCOL])


def free_port() -> int:
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        return listener.getsockname()[1]


def wait_for_backend(port: int, process: subprocess.Popen) -> None:
    for _ in range(150):
        try:
            urllib.request.urlopen(f"http://127.0.0.1:{port}/login", timeout=0.2).close()
            return
        except Exception:
            time.sleep(0.1)
        if process.poll() is not None:
            raise RuntimeError("Backend exited before readiness")
    raise RuntimeError("Backend did not become ready")


def wait_for_proxy(port: int, context: ssl.SSLContext, process: subprocess.Popen) -> None:
    for _ in range(150):
        try:
            connection = http.client.HTTPSConnection("localhost", port, context=context, timeout=0.3)
            connection.request("GET", "/login")
            response = connection.getresponse()
            response.read()
            connection.close()
            if response.status == 200:
                return
        except Exception:
            time.sleep(0.1)
        if process.poll() is not None:
            raise RuntimeError("Caddy exited before readiness")
    raise RuntimeError("Caddy did not become ready")


async def browser_round_trip(port: int, context: ssl.SSLContext, cookie: str) -> None:
    origin = f"https://localhost:{port}"
    uri = f"wss://localhost:{port}/ws"
    try:
        async with connect(uri, origin=origin, ssl=ssl.create_default_context()):
            pass
    except ssl.SSLCertVerificationError:
        pass
    else:
        raise AssertionError("Untrusted proxy certificate was accepted")

    async with connect(uri, origin=origin, ssl=context, additional_headers={"Cookie": cookie}) as browser:
        for _ in range(100):
            await browser.send(json.dumps({"type": "list_devices"}))
            listing = json.loads(await browser.recv())
            if "proxy-agent" in listing["devices"]:
                break
            await asyncio.sleep(0.1)
        else:
            raise RuntimeError("Agent did not register through Caddy")
        await browser.send(json.dumps({"type": "start_session", "deviceId": "proxy-agent"}))
        session = json.loads(await browser.recv())["sessionId"]
        ready = json.loads(await asyncio.wait_for(browser.recv(), 3))
        if ready != {"type": "session_ready", "sessionId": session}:
            raise AssertionError(f"Session did not become ready: {ready}")
        command = "printf 'PROXY_%s\\n' VERIFIED\n"
        await browser.send(json.dumps({"type": "term_input", "sessionId": session, "input": base64.b64encode(command.encode()).decode()}))
        output = ""
        for _ in range(40):
            message = json.loads(await asyncio.wait_for(browser.recv(), 2))
            if message["type"] == "term_data":
                output += base64.b64decode(message["data"]).decode(errors="replace")
            if "PROXY_VERIFIED" in output:
                return
        raise AssertionError("Expected shell output did not arrive through Caddy")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--caddy", required=True, type=Path, help="Path to a Caddy 2 executable")
    args = parser.parse_args()
    if not args.caddy.is_file():
        parser.error("Caddy executable not found")

    with tempfile.TemporaryDirectory(prefix="aetherterm-caddy-check-") as directory:
        base = Path(directory)
        cert, key = base / "cert.pem", base / "key.pem"
        subprocess.run(
            ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1", "-subj", "/CN=localhost",
             "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1", "-keyout", str(key), "-out", str(cert)],
            check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        operator, agents, token_file = base / "operator.json", base / "agents.json", base / "agent.token"
        initialize_operator(operator, "ephemeral-test-password")
        issue_credential(agents, "proxy-agent", token_file)
        backend_port, proxy_port = free_port(), free_port()
        config = base / "Caddyfile"
        config.write_text(
            f"{{\n  auto_https disable_redirects\n  admin off\n}}\n"
            f"https://localhost:{proxy_port} {{\n  tls {cert} {key}\n  reverse_proxy 127.0.0.1:{backend_port}\n}}\n",
            encoding="utf-8",
        )
        subprocess.run([str(args.caddy), "validate", "--config", str(config), "--adapter", "caddyfile"],
                       check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        env = {
            **os.environ, "AETHERTERM_OPERATOR_FILE": str(operator), "AETHERTERM_AGENTS_FILE": str(agents),
            "PYTHONDONTWRITEBYTECODE": "1", "PYTHONUNBUFFERED": "1",
            "XDG_DATA_HOME": str(base / "caddy-data"), "XDG_CONFIG_HOME": str(base / "caddy-config"),
        }
        processes: list[tuple[subprocess.Popen, object, str]] = []

        def start(command: list[str], name: str) -> subprocess.Popen:
            log = open(base / f"{name}.log", "w+", encoding="utf-8")
            process = subprocess.Popen(command, cwd=ROOT, env=env, stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
            processes.append((process, log, name))
            return process

        try:
            backend = start([sys.executable, "-m", "uvicorn", "server.main:app", "--host", "127.0.0.1", "--port",
                             str(backend_port), "--proxy-headers", "--forwarded-allow-ips", "127.0.0.1"], "backend")
            wait_for_backend(backend_port, backend)
            proxy = start([str(args.caddy), "run", "--config", str(config), "--adapter", "caddyfile"], "proxy")
            context = ssl.create_default_context(cafile=str(cert))
            wait_for_proxy(proxy_port, context, proxy)
            origin = f"https://localhost:{proxy_port}"
            connection = http.client.HTTPSConnection("localhost", proxy_port, context=context, timeout=2)
            connection.request("POST", "/login", "password=ephemeral-test-password", headers={"Origin": origin})
            response = connection.getresponse()
            if response.status != 303:
                raise AssertionError(f"Sign-in returned {response.status}")
            cookie_header = response.getheader("set-cookie")
            if "Secure" not in cookie_header:
                raise AssertionError("HTTPS session cookie lacks Secure")
            cookie = cookie_header.split(";", 1)[0]
            response.read()
            connection.close()
            start([sys.executable, "client/main.py", "--host", "localhost", "--port", str(proxy_port),
                   "--device-id", "proxy-agent", "--token-file", str(token_file), "--tls", "--ca-file", str(cert)], "agent")
            asyncio.run(browser_round_trip(proxy_port, context, cookie))
            print("Caddy HTTPS/WSS certificate and real PTY round trip: PASS")
        except BaseException:
            for _, log, name in processes:
                log.flush()
                log.seek(0)
                print(f"{name} log tail:\n{log.read()[-2000:]}", file=sys.stderr)
            raise
        finally:
            for process, _, _ in reversed(processes):
                try:
                    os.killpg(process.pid, signal.SIGTERM)
                except ProcessLookupError:
                    pass
            for process, log, _ in reversed(processes):
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    os.killpg(process.pid, signal.SIGKILL)
                    process.wait(timeout=5)
                log.close()


if __name__ == "__main__":
    main()
