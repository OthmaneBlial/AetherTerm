import asyncio
import websockets
import json
import argparse
import pty
import os
import select
import base64
import termios
import struct
import fcntl
import time
from pathlib import Path
import stat
import ipaddress
import ssl


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
            async with websockets.connect(uri, ssl=tls_context) as websocket:
                # register
                await websocket.send(json.dumps({"type": "register", "deviceId": device_id, "token": token, "description": description}))
                response = await websocket.recv()
                msg = json.loads(response)
                if msg['type'] == 'registered':
                    print("Agent registered with the AetherTerm prototype.")
                    print("WSS certificate verified." if tls else "Local WS connection established; use loopback only.")
                else:
                    print("❌ Registration failed - Invalid token or server error")
                    return

                pty_started = False
                pid = None
                fd = None
                session_id = None

                async def read_pty():
                    nonlocal pty_started, fd, websocket, session_id
                    while pty_started:
                        loop = asyncio.get_event_loop()
                        r, w, e = await loop.run_in_executor(None, lambda: select.select([fd], [], [], 0.1))
                        if r:
                            data = await loop.run_in_executor(None, lambda: os.read(fd, 1024))
                            if data:
                                encoded = base64.b64encode(data).decode()
                                await websocket.send(json.dumps({"type": "term_data", "sessionId": session_id, "data": encoded}))

                read_task = None

                async def heartbeat():
                    while True:
                        await asyncio.sleep(30)
                        try:
                            await websocket.send(json.dumps({"type": "heartbeat"}))
                        except:
                            break

                heartbeat_task = asyncio.create_task(heartbeat())

                try:
                    while True:
                        data = await websocket.recv()
                        msg = json.loads(data)
                        if msg['type'] == 'login_request':
                            session_id = msg['sessionId']
                            if not pty_started:
                                pid, fd = pty.fork()
                                if pid == 0:
                                    os.execv('/bin/bash', ['/bin/bash'])
                                else:
                                    pty_started = True
                                    read_task = asyncio.create_task(read_pty())
                                    print("Terminal started")
                                    # Send initial prompt by writing to PTY
                                    os.write(fd, b'echo "Terminal connected - type commands!"\n')
                        elif msg['type'] == 'term_data' and pty_started:
                            input_data = base64.b64decode(msg['data'])
                            os.write(fd, input_data)
                        elif msg['type'] == 'resize' and pty_started:
                            cols = msg['cols']
                            rows = msg['rows']
                            size = struct.pack('HHHH', rows, cols, 0, 0)
                            fcntl.ioctl(fd, termios.TIOCSWINSZ, size)
                        elif msg['type'] == 'heartbeat_ack':
                            pass  # handle heartbeat
                except Exception as e:
                    print(f"WS error: {e}")
                finally:
                    if read_task:
                        read_task.cancel()
                    if heartbeat_task:
                        heartbeat_task.cancel()
                    if pty_started:
                        os.close(fd)
                        os.kill(pid, 9)
        except Exception as e:
            print(f"Connection failed: {e}, retrying in {backoff}s")
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
    parser.add_argument('--reconnect', action='store_true', help='Enable auto-reconnect')
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
    asyncio.run(connect(args.host, args.port, args.device_id, token, args.description, tls=args.tls, ca_file=args.ca_file))

if __name__ == '__main__':
    main()
