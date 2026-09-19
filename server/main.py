from fastapi import FastAPI, Request, WebSocket
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse, PlainTextResponse, RedirectResponse
import asyncio
import json
import uuid
from urllib.parse import parse_qs

from .auth import COOKIE_NAME, SESSION_SECONDS, OperatorAuth, operator_file

app = FastAPI()
operator_auth = OperatorAuth(operator_file())

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

print("AetherTerm prototype: operator login protects browser access; agent credentials still need replacement.")

devices = {}  # device_id: websocket
sessions = {}  # session_id: {'device_id': str, 'web_ws': WebSocket}
active_connections = {}  # client_ip: connection_info


def same_origin(request: Request) -> bool:
    return request.headers.get("origin") == f"{request.url.scheme}://{request.headers.get('host')}"


def login_page(message: str = "") -> HTMLResponse:
    notice = "<p role='alert'>Sign in failed.</p>" if message else ""
    if not operator_auth.configured():
        notice = "<p role='alert'>Operator setup required. Run <code>python -m server.admin init</code> on the server, then restart it.</p>"
    body = f"""<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>AetherTerm sign in</title><style>body{{font:16px system-ui;background:#171b20;color:#f1f5f9;margin:0;display:grid;min-height:100vh;place-items:center}}
main{{width:min(90vw,380px);background:#222a33;padding:2rem;border-radius:12px}}label,input,button{{display:block;width:100%;box-sizing:border-box}}
input,button{{font:inherit;padding:.8rem;margin:.7rem 0 1rem;border-radius:6px}}button{{background:#6ee7b7;border:0;cursor:pointer}}a{{color:#6ee7b7}}</style>
<main><h1>AetherTerm</h1><p>Sign in to the operator console.</p>{notice}<form method="post" action="/login">
<label for="password">Operator password</label><input id="password" name="password" type="password" autocomplete="current-password" required>
<button type="submit">Sign in</button></form><p>Run only on loopback until remote TLS setup is complete.</p></main></html>"""
    return HTMLResponse(body, headers={"Cache-Control": "no-store"})


@app.middleware("http")
async def protect_web(request: Request, call_next):
    if request.url.path.startswith("/web") and not operator_auth.session_key(request.cookies.get(COOKIE_NAME)):
        return RedirectResponse("/login", status_code=303)
    response = await call_next(request)
    if request.url.path.startswith("/web"):
        response.headers["Cache-Control"] = "no-store"
    return response


@app.get("/login")
async def show_login(request: Request):
    if operator_auth.session_key(request.cookies.get(COOKIE_NAME)):
        return RedirectResponse("/web/", status_code=303)
    return login_page()


@app.post("/login")
async def sign_in(request: Request):
    if not same_origin(request):
        return PlainTextResponse("Forbidden", status_code=403)
    if not operator_auth.configured():
        return PlainTextResponse("Operator setup required", status_code=503)
    client_ip = request.client.host if request.client else "unknown"
    if not operator_auth.allow_login(client_ip):
        return PlainTextResponse("Too many attempts", status_code=429)
    body = await request.body()
    if len(body) > 4096:
        return PlainTextResponse("Request too large", status_code=413)
    password = parse_qs(body.decode("utf-8", errors="replace")).get("password", [""])[0]
    if not operator_auth.verify_password(password):
        response = login_page("invalid")
        response.status_code = 401
        return response
    token = operator_auth.create_session()
    response = RedirectResponse("/web/", status_code=303)
    response.set_cookie(
        COOKIE_NAME, token, max_age=SESSION_SECONDS, httponly=True,
        secure=request.url.scheme == "https", samesite="strict", path="/",
    )
    response.headers["Cache-Control"] = "no-store"
    return response


@app.post("/logout")
async def sign_out(request: Request):
    if not same_origin(request):
        return PlainTextResponse("Forbidden", status_code=403)
    await operator_auth.revoke(request.cookies.get(COOKIE_NAME))
    response = RedirectResponse("/login", status_code=303)
    response.delete_cookie(COOKIE_NAME, path="/")
    return response

@app.websocket("/ws")
async def web_websocket(websocket: WebSocket):
    client_ip = websocket.client.host if websocket.client else "unknown"
    expected_origin = f"{'https' if websocket.url.scheme == 'wss' else 'http'}://{websocket.headers.get('host')}"
    session_key = operator_auth.session_key(websocket.cookies.get(COOKIE_NAME))
    if websocket.headers.get("origin") != expected_origin or session_key is None:
        log_security_event("WEB_ACCESS_DENIED", client_ip)
        await websocket.close(code=1008, reason="Authentication or origin required")
        return

    # Security check: Rate limiting
    if is_rate_limited(client_ip):
        log_security_event("RATE_LIMITED", client_ip, "Too many connection attempts")
        await websocket.close(code=1008, reason="Rate limit exceeded")
        return

    await websocket.accept()
    operator_auth.register_socket(session_key, websocket)
    log_security_event("WEB_CONNECTION_ESTABLISHED", client_ip, "Web client connected")

    try:
        while True:
            remaining = operator_auth.seconds_remaining(session_key)
            if remaining <= 0:
                await websocket.close(code=1008, reason="Session expired")
                break
            try:
                data = await asyncio.wait_for(websocket.receive_text(), timeout=min(remaining, 1.0))
            except asyncio.TimeoutError:
                continue
            if operator_auth.seconds_remaining(session_key) <= 0:
                await websocket.close(code=1008, reason="Session expired")
                break
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
                if session_id not in sessions or sessions[session_id]['web_ws'] is not websocket:
                    log_security_event("INVALID_SESSION", client_ip)
                    await websocket.send_text(json.dumps({"type": "error", "message": "Session unavailable"}))
                    continue
                device_id = sessions[session_id]['device_id']
                await devices[device_id].send_text(json.dumps({"type": "term_data", "sessionId": session_id, "data": input_b64}))
            elif msg['type'] == 'resize':
                session_id = msg['sessionId']
                cols = msg.get('cols', 80)
                rows = msg.get('rows', 24)
                if session_id in sessions and sessions[session_id]['web_ws'] is websocket:
                    device_id = sessions[session_id]['device_id']
                    await devices[device_id].send_text(json.dumps({"type": "resize", "sessionId": session_id, "cols": cols, "rows": rows}))
                else:
                    await websocket.send_text(json.dumps({"type": "error", "message": "Session unavailable"}))
    except Exception as e:
        log_security_event("WEB_ERROR", client_ip, str(e))
        print(f"Web WS error: {e}")
    finally:
        operator_auth.unregister_socket(session_key, websocket)
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
                    log_security_event("INVALID_TOKEN", client_ip, f"Device: {device_id}")
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
                log_security_event("CLIENT_REGISTERED", client_ip, f"Device: {device_id}")
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
async def root(request: Request):
    destination = "/web/" if operator_auth.session_key(request.cookies.get(COOKIE_NAME)) else "/login"
    return RedirectResponse(destination, status_code=303)
