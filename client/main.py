import asyncio
import websockets
import json
import argparse
import os
import base64
from pathlib import Path
import stat
import ipaddress
import ssl
import signal

WEBSOCKET_SUBPROTOCOL = "aetherterm.v1"

if __package__:
    from .sessions import PtySession
else:
    from sessions import PtySession


def read_token_file(path: Path) -> str:
    path = path.expanduser()
    if path.is_symlink():
        raise ValueError("Token file must not be a symbolic link")
    info = path.stat()
    if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
        raise ValueError("Token file must be a private regular file owned by this user (mode 0600)")
    token = path.read_text(encoding="utf-8").strip()
    if not token or len(token) > 256 or any(character.isspace() for character in token):
        raise ValueError("Token file contains an invalid credential")
    return token

def server_uri(host: str, port: int, tls: bool) -> str:
    if not host or any(character in host for character in "/@?# ") or not 1 <= port <= 65535:
        raise ValueError("Invalid server host or port")
    try:
        loopback = ipaddress.ip_address(host).is_loopback
    except ValueError:
        loopback = host.lower() == "localhost"
    if not tls and not loopback:
        raise ValueError("Remote agents require --tls and a verified WSS server")
    formatted_host = f"[{host}]" if ":" in host and not host.startswith("[") else host
    return f"{'wss' if tls else 'ws'}://{formatted_host}:{port}/client"


async def connect(host, port, device_id, token, description, *, tls=False, ca_file=None):
    uri = server_uri(host, port, tls)
    tls_context = ssl.create_default_context(cafile=str(ca_file) if ca_file else None) if tls else None
    backoff = 1
    while True:
        try:
            async with websockets.connect(uri, ssl=tls_context, open_timeout=5, close_timeout=2,
                                          subprotocols=[WEBSOCKET_SUBPROTOCOL]) as websocket:
                # register
                await websocket.send(json.dumps({"type": "register", "deviceId": device_id, "token": token, "description": description}))
                response = await websocket.recv()
                msg = json.loads(response)
                if msg['type'] == 'registered':
                    backoff = 1
                    print("Agent registered with the AetherTerm prototype.")
                    print("WSS certificate verified." if tls else "Local WS connection established; use loopback only.")
                else:
                    print("❌ Registration failed - Invalid token or server error")
                    return

                sessions: dict[str, PtySession] = {}

                async def send(message: dict) -> None:
                    await websocket.send(json.dumps(message))

                async def session_exited(session_id: str) -> None:
                    session = sessions.pop(session_id, None)
                    if session is not None:
                        try:
                            await send({"type": "session_exit", "sessionId": session_id})
                        except websockets.exceptions.ConnectionClosed:
                            pass
                        finally:
                            await session.close()

                async def heartbeat():
                    while True:
                        await asyncio.sleep(30)
                        try:
                            await send({"type": "heartbeat"})
                        except websockets.exceptions.ConnectionClosed:
                            break

                heartbeat_task = asyncio.create_task(heartbeat())

                try:
                    while True:
                        data = await websocket.recv()
                        msg = json.loads(data)
                        if msg['type'] == 'login_request':
                            session_id = msg['sessionId']
                            if session_id in sessions:
                                continue
                            session = PtySession(session_id, send, session_exited)
                            sessions[session_id] = session
                            try:
                                session.start()
                            except OSError:
                                sessions.pop(session_id, None)
                                await send({"type": "session_exit", "sessionId": session_id})
                                continue
                            await send({"type": "session_ready", "sessionId": session_id})
                        elif msg['type'] == 'close_session':
                            session = sessions.pop(msg['sessionId'], None)
                            if session is not None:
                                await session.close()
                        elif msg['type'] == 'term_data':
                            session = sessions.get(msg['sessionId'])
                            if session is not None:
                                session.write(base64.b64decode(msg['data'], validate=True))
                        elif msg['type'] == 'resize':
                            session = sessions.get(msg['sessionId'])
                            if session is not None:
                                session.resize(msg['cols'], msg['rows'])
                        elif msg['type'] == 'heartbeat_ack':
                            pass  # handle heartbeat
                except websockets.exceptions.ConnectionClosed as exc:
                    print(f"Agent connection closed: {exc.code}")
                    if exc.code == 1008 and exc.reason == "Device revoked or credential rotated":
                        print("Device credential was revoked or rotated; stopping agent.")
                        return
                finally:
                    heartbeat_task.cancel()
                    await asyncio.gather(heartbeat_task, return_exceptions=True)
                    await asyncio.gather(*(session.close() for session in sessions.values()), return_exceptions=True)
                    sessions.clear()
        except ssl.SSLCertVerificationError:
            print("WSS certificate validation failed; stopping agent.")
            return
        except (OSError, websockets.exceptions.WebSocketException) as exc:
            print(f"Connection unavailable ({type(exc).__name__}); retrying in {backoff}s")
        await asyncio.sleep(backoff)
        backoff = min(backoff * 2, 60)

def main():
    parser = argparse.ArgumentParser(description="AetherTerm Client")
    parser.add_argument('--host', required=True, help='Server host')
    parser.add_argument('--port', type=int, required=True, help='Server port')
    parser.add_argument('--device-id', required=True, help='Unique device ID')
    parser.add_argument('--token-file', required=True, type=Path, help='Private 0600 agent credential file')
    parser.add_argument('--description', default='', help='Device description')
    parser.add_argument('--tls', action='store_true', help='Use WSS with certificate validation')
    parser.add_argument('--ca-file', type=Path, help='Optional trusted CA bundle for WSS')
    args = parser.parse_args()

    try:
        token = read_token_file(args.token_file)
        server_uri(args.host, args.port, args.tls)
        if args.ca_file and not args.tls:
            raise ValueError("--ca-file requires --tls")
        if args.ca_file and not args.ca_file.is_file():
            raise ValueError("CA file not found")
    except (OSError, UnicodeError, ValueError) as exc:
        parser.error(str(exc))
    async def run_agent():
        task = asyncio.current_task()
        asyncio.get_running_loop().add_signal_handler(signal.SIGTERM, task.cancel)
        await connect(args.host, args.port, args.device_id, token, args.description, tls=args.tls, ca_file=args.ca_file)

    try:
        asyncio.run(run_agent())
    except (asyncio.CancelledError, KeyboardInterrupt):
        pass

if __name__ == '__main__':
    main()
