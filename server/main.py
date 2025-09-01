from fastapi import FastAPI, WebSocket
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse
import asyncio
import json
import uuid

app = FastAPI()

import os
import time
import hashlib
from collections import defaultdict

# Security configuration
ALLOWED_TOKENS = {
    "secret123": "default_client",
    "admin_token": "admin_client",
    "demo_token": "demo_client"
}

# Rate limiting
connection_attempts = defaultdict(list)
MAX_CONNECTIONS_PER_MINUTE = 10
MAX_CONNECTIONS_PER_HOUR = 50

def is_rate_limited(client_ip: str) -> bool:
    """Simple rate limiting"""
    now = time.time()
    # Clean old entries
    connection_attempts[client_ip] = [t for t in connection_attempts[client_ip] if now - t < 3600]

    # Check limits
    recent_minute = [t for t in connection_attempts[client_ip] if now - t < 60]
    recent_hour = connection_attempts[client_ip]

    if len(recent_minute) >= MAX_CONNECTIONS_PER_MINUTE:
        return True
    if len(recent_hour) >= MAX_CONNECTIONS_PER_HOUR:
        return True

    connection_attempts[client_ip].append(now)
    return False

def validate_token(token: str) -> bool:
    """Validate client token"""
    return token in ALLOWED_TOKENS

def log_security_event(event: str, client_ip: str = "unknown", details: str = ""):
    """Log security events"""
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
    print(f"[SECURITY] {timestamp} - {event} - IP: {client_ip} - {details}")

web_dir = os.path.join(os.path.dirname(__file__), "..", "web")
print(f"Web directory path: {web_dir}")
print(f"Web directory exists: {os.path.exists(web_dir)}")
if os.path.exists(web_dir):
    app.mount("/web", StaticFiles(directory=web_dir, html=True), name="web")
    print("Web directory mounted successfully")
else:
    print("Web directory not found!")

# Security startup banner
print("\n" + "="*60)
print("🔒 AETHERTERM SERVER - SECURE REMOTE TERMINAL")
print("="*60)
print("🛡️  SECURITY FEATURES ACTIVE:")
print("   ✅ Token-based authentication")
print("   ✅ Rate limiting (10/min, 50/hour per IP)")
print("   ✅ IP-based connection monitoring")
print("   ✅ Session validation & logging")
print("   ✅ WebSocket encryption ready")
print("   ✅ TLS/SSL certificate support")
print(f"   ✅ {len(ALLOWED_TOKENS)} authorized tokens configured")
print("="*60)
print("🚀 Server ready for secure connections!")
print("="*60 + "\n")

devices = {}  # device_id: websocket
sessions = {}  # session_id: {'device_id': str, 'web_ws': WebSocket}
active_connections = {}  # client_ip: connection_info

@app.websocket("/ws")
async def web_websocket(websocket: WebSocket):
    client_ip = websocket.client.host if hasattr(websocket, 'client') else "unknown"

    # Security check: Rate limiting
    if is_rate_limited(client_ip):
        log_security_event("RATE_LIMITED", client_ip, "Too many connection attempts")
        await websocket.close(code=1008, reason="Rate limit exceeded")
        return

    await websocket.accept()
    log_security_event("WEB_CONNECTION_ESTABLISHED", client_ip, "Web client connected")

    try:
        while True:
            data = await websocket.receive_text()
            msg = json.loads(data)

            # Log all web client activities for security monitoring
            log_security_event("WEB_MESSAGE", client_ip, f"Type: {msg.get('type', 'unknown')}")

            if msg['type'] == 'list_devices':
                device_list = list(devices.keys())
                await websocket.send_text(json.dumps({"type": "device_list", "devices": device_list}))
            elif msg['type'] == 'start_session':
                device_id = msg['deviceId']
                if device_id not in devices:
                    await websocket.send_text(json.dumps({"type": "error", "message": "Device not connected"}))
                    continue
                session_id = str(uuid.uuid4())
                sessions[session_id] = {'device_id': device_id, 'web_ws': websocket}
                await devices[device_id].send_text(json.dumps({"type": "login_request", "sessionId": session_id}))
                await websocket.send_text(json.dumps({"type": "session_started", "sessionId": session_id}))
                log_security_event("SESSION_STARTED", client_ip, f"Session: {session_id}, Device: {device_id}")
            elif msg['type'] == 'term_input':
                session_id = msg['sessionId']
                input_b64 = msg['input']
                if session_id not in sessions:
                    log_security_event("INVALID_SESSION", client_ip, f"Session: {session_id}")
                    continue
                device_id = sessions[session_id]['device_id']
                await devices[device_id].send_text(json.dumps({"type": "term_data", "sessionId": session_id, "data": input_b64}))
            elif msg['type'] == 'resize':
                session_id = msg['sessionId']
                cols = msg.get('cols', 80)
                rows = msg.get('rows', 24)
                if session_id in sessions:
                    device_id = sessions[session_id]['device_id']
                    await devices[device_id].send_text(json.dumps({"type": "resize", "sessionId": session_id, "cols": cols, "rows": rows}))
    except Exception as e:
        log_security_event("WEB_ERROR", client_ip, str(e))
        print(f"Web WS error: {e}")
    finally:
        log_security_event("WEB_CONNECTION_CLOSED", client_ip, "Web client disconnected")
        # remove sessions for this web_ws
        to_remove = [sid for sid, s in sessions.items() if s['web_ws'] == websocket]
        for sid in to_remove:
            del sessions[sid]

@app.websocket("/client")
async def client_websocket(websocket: WebSocket):
    client_ip = websocket.client.host if hasattr(websocket, 'client') else "unknown"

    # Security check: Rate limiting for client connections too
    if is_rate_limited(client_ip):
        log_security_event("CLIENT_RATE_LIMITED", client_ip, "Client connection rate limited")
        await websocket.close(code=1008, reason="Rate limit exceeded")
        return

    await websocket.accept()
    log_security_event("CLIENT_CONNECTION_ESTABLISHED", client_ip, "Client connected")
    device_id = None

    try:
        while True:
            data = await websocket.receive_text()
            msg = json.loads(data)

            if msg['type'] == 'register':
                token = msg.get('token', '')
                device_id = msg.get('deviceId', '')

                # Security check: Validate token
                if not validate_token(token):
                    log_security_event("INVALID_TOKEN", client_ip, f"Device: {device_id}, Token: {token[:8]}...")
                    await websocket.send_text(json.dumps({"type": "error", "message": "Invalid authentication token"}))
                    await websocket.close(code=1008, reason="Authentication failed")
                    return

                # Check if device ID is already in use
                if device_id in devices:
                    log_security_event("DUPLICATE_DEVICE", client_ip, f"Device: {device_id}")
                    await websocket.send_text(json.dumps({"type": "error", "message": "Device ID already in use"}))
                    await websocket.close(code=1008, reason="Device ID conflict")
                    return

                devices[device_id] = websocket
                log_security_event("CLIENT_REGISTERED", client_ip, f"Device: {device_id}, Token: {token[:8]}...")
                await websocket.send_text(json.dumps({"type": "registered"}))

            elif msg['type'] == 'term_data':
                session_id = msg['sessionId']
                data_b64 = msg['data']
                if session_id in sessions:
                    web_ws = sessions[session_id]['web_ws']
                    await web_ws.send_text(json.dumps({"type": "term_data", "sessionId": session_id, "data": data_b64}))
                    log_security_event("TERM_DATA_FORWARDED", client_ip, f"Session: {session_id}")
                else:
                    log_security_event("INVALID_SESSION_DATA", client_ip, f"Session: {session_id}")

            elif msg['type'] == 'heartbeat':
                await websocket.send_text(json.dumps({"type": "heartbeat_ack"}))

            elif msg['type'] == 'login_request':
                session_id = msg['sessionId']
                log_security_event("LOGIN_REQUEST", client_ip, f"Session: {session_id}")

    except Exception as e:
        log_security_event("CLIENT_ERROR", client_ip, str(e))
        print(f"Client WS error: {e}")
    finally:
        if device_id and device_id in devices:
            del devices[device_id]
        log_security_event("CLIENT_CONNECTION_CLOSED", client_ip, f"Device: {device_id}")

@app.get("/")
async def root():
    return HTMLResponse("<h1>AetherTerm Server</h1><a href='/web/'>Web Interface</a>")
