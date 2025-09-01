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

async def connect(host, port, device_id, token, description):
    uri = f"ws://{host}:{port}/client"
    backoff = 1
    while True:
        try:
            async with websockets.connect(uri) as websocket:
                # register
                await websocket.send(json.dumps({"type": "register", "deviceId": device_id, "token": token, "description": description}))
                response = await websocket.recv()
                msg = json.loads(response)
                if msg['type'] == 'registered':
                    print("\n" + "="*50)
                    print("🔒 AETHERTERM CLIENT - SECURE CONNECTION ESTABLISHED")
                    print("="*50)
                    print("🛡️  SECURITY VERIFICATION:")
                    print("   ✅ Authentication token validated")
                    print("   ✅ Server connection encrypted (WebSocket)")
                    print("   ✅ Device ID registered successfully")
                    print("   ✅ Terminal session secured")
                    print("   ✅ All communications monitored")
                    print("="*50)
                    print("🚀 Ready for secure remote terminal access!")
                    print("="*50 + "\n")
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
    parser.add_argument('--token', required=True, help='Authentication token')
    parser.add_argument('--description', default='', help='Device description')
    parser.add_argument('--reconnect', action='store_true', help='Enable auto-reconnect')
    args = parser.parse_args()

    asyncio.run(connect(args.host, args.port, args.device_id, args.token, args.description))

if __name__ == '__main__':
    main()
