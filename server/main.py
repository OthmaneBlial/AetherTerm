from fastapi import FastAPI, Request, WebSocket
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, HTMLResponse, PlainTextResponse, RedirectResponse
import asyncio
import json
from pathlib import Path
import re
import uuid
from urllib.parse import parse_qs

from .agents import AgentRegistry, agents_file
from .auth import COOKIE_NAME, SESSION_SECONDS, OperatorAuth, operator_file
from .network import transport_allowed
from .limits import (ConnectionLimiter, SlidingWindowLimiter, MAX_CONNECTED_AGENTS,
                     MAX_SESSIONS_PER_AGENT, MAX_SESSIONS_PER_BROWSER, MAX_SESSIONS_TOTAL,
                     SESSION_START_TIMEOUT)
from .protocol import ProtocolError, parse_message

app = FastAPI()
operator_auth = OperatorAuth(operator_file())
agent_registry = AgentRegistry(agents_file())

import os
import time

browser_connections = ConnectionLimiter()
agent_connections = ConnectionLimiter()

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

print("AetherTerm prototype: operator and device credentials are required.")

devices = {}  # device_id: websocket
device_credentials = {}  # device_id: credential hash for revocation checks
sessions = {}  # session_id: {'device_id': str, 'web_ws': WebSocket, 'ready': bool}
device_last_seen = {}  # device_id: Unix timestamp, only for this server process
device_descriptions = {}  # agent-supplied fallback, never an identity claim

SEND_TIMEOUT = 3


async def send_json(websocket: WebSocket, message: dict, timeout: float = SEND_TIMEOUT) -> None:
    """A slow peer cannot hold a browser or agent receive loop indefinitely."""
    await asyncio.wait_for(websocket.send_text(json.dumps(message)), timeout=timeout)


async def send_error(websocket: WebSocket, message: str) -> None:
    await send_json(websocket, {"type": "error", "message": message})


async def send_to_browser(session_id: str, message: dict) -> bool:
    """Drop one stalled browser session without taking down its agent."""
    session = sessions.get(session_id)
    if session is None:
        return False
    try:
        await send_json(session['web_ws'], message)
        return True
    except Exception:
        sessions.pop(session_id, None)
        device_socket = devices.get(session['device_id'])
        if device_socket:
            try:
                await send_json(device_socket, {"type": "close_session", "sessionId": session_id})
            except Exception:
                pass
        return False


def session_capacity(websocket: WebSocket, device_id: str) -> bool:
    if len(sessions) >= MAX_SESSIONS_TOTAL:
        return False
    if sum(session["web_ws"] is websocket for session in sessions.values()) >= MAX_SESSIONS_PER_BROWSER:
        return False
    return sum(session["device_id"] == device_id for session in sessions.values()) < MAX_SESSIONS_PER_AGENT


async def expire_pending_session(session_id: str) -> None:
    await asyncio.sleep(SESSION_START_TIMEOUT)
    session = sessions.get(session_id)
    if session is None or session['ready']:
        return
    await send_to_browser(session_id, {"type": "session_closed", "sessionId": session_id,
                                       "reason": "Shell did not become ready"})
    session = sessions.pop(session_id, None)
    if session:
        device_socket = devices.get(session['device_id'])
        if device_socket:
            try:
                await send_json(device_socket, {"type": "close_session", "sessionId": session_id})
            except Exception:
                pass


def active_device(device_id: str) -> bool:
    token_hash = device_credentials.get(device_id)
    return bool(device_id in devices and token_hash and agent_registry.is_active(device_id, token_hash))


def same_origin(request: Request) -> bool:
    return request.headers.get("origin") == f"{request.url.scheme}://{request.headers.get('host')}"


def login_page(message: str = "") -> HTMLResponse:
    notice = '<p class="error" role="alert">Sign in failed. Check the password and try again.</p>' if message else ""
    if not operator_auth.configured():
        notice = ('<p class="error" role="alert">Operator setup required. Run '
                  '<code>python -m server.admin init</code> on the server, then restart it.</p>')
    body = (Path(web_dir) / "login.html").read_text(encoding="utf-8").replace("<!-- SERVER_NOTICE -->", notice)
    return HTMLResponse(body, headers={"Cache-Control": "no-store"})


def content_security_policy(request: Request) -> str:
    host = request.headers.get("host", "")
    websocket_source = ""
    if re.fullmatch(r"[A-Za-z0-9.:[\]-]+", host):
        websocket_source = f" {'wss' if request.url.scheme == 'https' else 'ws'}://{host}"
    return ("default-src 'none'; base-uri 'none'; object-src 'none'; frame-ancestors 'none'; "
            "form-action 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; "
            f"img-src 'self' data:; font-src 'self'; connect-src 'self'{websocket_source}")


@app.middleware("http")
async def protect_web(request: Request, call_next):
    if not transport_allowed(request.url.scheme, request.client.host if request.client else "unknown"):
        return PlainTextResponse("HTTPS required for remote access", status_code=403)
    if request.url.path.startswith("/web") and not operator_auth.session_key(request.cookies.get(COOKIE_NAME)):
        return RedirectResponse("/login", status_code=303)
    response = await call_next(request)
    response.headers["Content-Security-Policy"] = content_security_policy(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "same-origin"
    response.headers["X-Frame-Options"] = "DENY"
    if request.url.path.startswith("/web"):
        response.headers["Cache-Control"] = "no-store"
    return response


@app.get("/favicon.svg")
async def favicon():
    return FileResponse(Path(web_dir) / "favicon.svg", media_type="image/svg+xml")


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
    if not transport_allowed(websocket.url.scheme, client_ip):
        await websocket.close(code=1008, reason="WSS required for remote access")
        return
    expected_origin = f"{'https' if websocket.url.scheme == 'wss' else 'http'}://{websocket.headers.get('host')}"
    session_key = operator_auth.session_key(websocket.cookies.get(COOKIE_NAME))
    if websocket.headers.get("origin") != expected_origin or session_key is None:
        log_security_event("WEB_ACCESS_DENIED", client_ip)
        await websocket.close(code=1008, reason="Authentication or origin required")
        return

    # Security check: Rate limiting
    if not browser_connections.allow(client_ip):
        log_security_event("RATE_LIMITED", client_ip, "Too many connection attempts")
        await websocket.close(code=1008, reason="Rate limit exceeded")
        return

    await websocket.accept()
    operator_auth.register_socket(session_key, websocket)
    message_rate = SlidingWindowLimiter(240, 1, max_keys=1)
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
            if not message_rate.allow("browser"):
                await websocket.close(code=1008, reason="Message rate exceeded")
                break
            try:
                msg = parse_message(data, "browser")
            except ProtocolError as exc:
                await send_error(websocket, str(exc))
                continue

            # Log all web client activities for security monitoring
            log_security_event("WEB_MESSAGE", client_ip, f"Type: {msg.get('type', 'unknown')}")

            if msg['type'] == 'list_devices':
                device_list = [device_id for device_id in devices if active_device(device_id)]
                device_details = []
                for record in agent_registry.visible_devices():
                    device_id = record["deviceId"]
                    device_details.append({
                        "deviceId": device_id,
                        "description": record["description"] or device_descriptions.get(device_id, ""),
                        "connected": device_id in device_list,
                        "lastSeen": device_last_seen.get(device_id),
                    })
                await send_json(websocket, {"type": "device_list", "devices": device_list,
                                            "deviceDetails": device_details})
            elif msg['type'] == 'start_session':
                device_id = msg['deviceId']
                if not active_device(device_id):
                    await send_error(websocket, "Device not connected")
                    continue
                if not session_capacity(websocket, device_id):
                    await send_error(websocket, "Session limit reached")
                    continue
                session_id = str(uuid.uuid4())
                sessions[session_id] = {'device_id': device_id, 'web_ws': websocket, 'ready': False}
                await send_json(websocket, {"type": "session_started", "sessionId": session_id, "deviceId": device_id})
                try:
                    await send_json(devices[device_id], {"type": "login_request", "sessionId": session_id})
                except Exception:
                    await send_to_browser(session_id, {"type": "session_closed", "sessionId": session_id,
                                                       "reason": "Agent unavailable"})
                    sessions.pop(session_id, None)
                    continue
                asyncio.create_task(expire_pending_session(session_id))
                log_security_event("SESSION_STARTED", client_ip, f"Session: {session_id}, Device: {device_id}")
            elif msg['type'] == 'term_input':
                session_id = msg['sessionId']
                input_b64 = msg['input']
                if session_id not in sessions or sessions[session_id]['web_ws'] is not websocket or not active_device(sessions[session_id]['device_id']):
                    log_security_event("INVALID_SESSION", client_ip)
                    await send_error(websocket, "Session unavailable")
                    continue
                if not sessions[session_id]['ready']:
                    await send_error(websocket, "Session not ready")
                    continue
                device_id = sessions[session_id]['device_id']
                await send_json(devices[device_id], {"type": "term_data", "sessionId": session_id, "data": input_b64})
            elif msg['type'] == 'resize':
                session_id = msg['sessionId']
                cols = msg.get('cols', 80)
                rows = msg.get('rows', 24)
                if session_id in sessions and sessions[session_id]['web_ws'] is websocket and sessions[session_id]['ready'] and active_device(sessions[session_id]['device_id']):
                    device_id = sessions[session_id]['device_id']
                    await send_json(devices[device_id], {"type": "resize", "sessionId": session_id, "cols": cols, "rows": rows})
                else:
                    await send_error(websocket, "Session unavailable")
            elif msg['type'] == 'close_session':
                session_id = msg['sessionId']
                session = sessions.get(session_id)
                if session is None or session['web_ws'] is not websocket:
                    await send_error(websocket, "Session unavailable")
                    continue
                del sessions[session_id]
                device_socket = devices.get(session['device_id'])
                if device_socket:
                    await send_json(device_socket, {"type": "close_session", "sessionId": session_id})
                await send_json(websocket, {"type": "session_closed", "sessionId": session_id})
    except Exception as e:
        log_security_event("WEB_ERROR", client_ip, str(e))
        print(f"Web WS error: {e}")
    finally:
        operator_auth.unregister_socket(session_key, websocket)
        log_security_event("WEB_CONNECTION_CLOSED", client_ip, "Web client disconnected")
        # remove sessions for this web_ws
        to_remove = [sid for sid, s in sessions.items() if s['web_ws'] == websocket]
        for sid in to_remove:
            session = sessions.pop(sid)
            device_socket = devices.get(session['device_id'])
            if device_socket:
                try:
                    await send_json(device_socket, {"type": "close_session", "sessionId": sid})
                except Exception:
                    pass

@app.websocket("/client")
async def client_websocket(websocket: WebSocket):
    client_ip = websocket.client.host if websocket.client else "unknown"
    if not transport_allowed(websocket.url.scheme, client_ip):
        await websocket.close(code=1008, reason="WSS required for remote access")
        return

    # Security check: Rate limiting for client connections too
    if not agent_connections.allow(client_ip):
        log_security_event("CLIENT_RATE_LIMITED", client_ip, "Client connection rate limited")
        await websocket.close(code=1008, reason="Rate limit exceeded")
        return

    await websocket.accept()
    log_security_event("CLIENT_CONNECTION_ESTABLISHED", client_ip, "Client connected")
    device_id = None
    token_hash = None
    message_rate = SlidingWindowLimiter(240, 1, max_keys=1)

    try:
        while True:
            if device_id and not agent_registry.is_active(device_id, token_hash):
                await websocket.close(code=1008, reason="Device revoked or credential rotated")
                break
            try:
                data = await asyncio.wait_for(websocket.receive_text(), timeout=1 if device_id else 5)
            except asyncio.TimeoutError:
                if device_id:
                    continue
                await websocket.close(code=1008, reason="Registration required")
                break
            if device_id and not agent_registry.is_active(device_id, token_hash):
                await websocket.close(code=1008, reason="Device revoked or credential rotated")
                break
            if not message_rate.allow("agent"):
                await websocket.close(code=1008, reason="Message rate exceeded")
                break
            try:
                msg = parse_message(data, "agent")
            except ProtocolError as exc:
                await send_error(websocket, str(exc))
                continue
            if device_id is not None:
                device_last_seen[device_id] = time.time()

            if msg['type'] == 'register':
                if device_id is not None:
                    await websocket.close(code=1008, reason="Already registered")
                    return
                requested_id = msg.get('deviceId', '')
                candidate_hash = agent_registry.authenticate(requested_id, msg.get('token', ''))
                if candidate_hash is None:
                    log_security_event("INVALID_AGENT_CREDENTIAL", client_ip)
                    await send_json(websocket, {"type": "error", "message": "Invalid device credential"})
                    await websocket.close(code=1008, reason="Authentication failed")
                    return

                if requested_id in devices:
                    log_security_event("DUPLICATE_DEVICE", client_ip, f"Device: {requested_id}")
                    await send_json(websocket, {"type": "error", "message": "Device ID already in use"})
                    await websocket.close(code=1008, reason="Device ID conflict")
                    return

                if len(devices) >= MAX_CONNECTED_AGENTS:
                    await send_error(websocket, "Device limit reached")
                    await websocket.close(code=1008, reason="Device limit reached")
                    return

                device_id = requested_id
                token_hash = candidate_hash
                devices[device_id] = websocket
                device_credentials[device_id] = token_hash
                device_last_seen[device_id] = time.time()
                device_descriptions[device_id] = msg.get('description', '')
                log_security_event("CLIENT_REGISTERED", client_ip, f"Device: {device_id}")
                await send_json(websocket, {"type": "registered"})

            elif device_id is None:
                await websocket.close(code=1008, reason="Registration required")
                return

            elif msg['type'] == 'term_data':
                session_id = msg['sessionId']
                data_b64 = msg['data']
                if session_id in sessions and sessions[session_id]['device_id'] == device_id and sessions[session_id]['ready']:
                    if await send_to_browser(session_id, {"type": "term_data", "sessionId": session_id, "data": data_b64}):
                        log_security_event("TERM_DATA_FORWARDED", client_ip, f"Session: {session_id}")
                else:
                    log_security_event("INVALID_SESSION_DATA", client_ip, f"Session: {session_id}")

            elif msg['type'] == 'session_ready':
                session_id = msg['sessionId']
                session = sessions.get(session_id)
                if session and session['device_id'] == device_id and not session['ready']:
                    session['ready'] = True
                    await send_to_browser(session_id, {"type": "session_ready", "sessionId": session_id})

            elif msg['type'] == 'session_exit':
                session_id = msg['sessionId']
                session = sessions.get(session_id)
                if session and session['device_id'] == device_id:
                    await send_to_browser(session_id, {"type": "session_closed", "sessionId": session_id})
                    sessions.pop(session_id, None)

            elif msg['type'] == 'heartbeat':
                await send_json(websocket, {"type": "heartbeat_ack"})

    except Exception as e:
        log_security_event("CLIENT_ERROR", client_ip, str(e))
        print(f"Client WS error: {e}")
    finally:
        if device_id and devices.get(device_id) is websocket:
            device_last_seen[device_id] = time.time()
            del devices[device_id]
            device_credentials.pop(device_id, None)
            for session_id, session in list(sessions.items()):
                if session['device_id'] == device_id:
                    del sessions[session_id]
                    try:
                        await send_json(session['web_ws'], {"type": "session_closed", "sessionId": session_id,
                                                            "reason": "Agent disconnected"})
                    except Exception:
                        pass
        log_security_event("CLIENT_CONNECTION_CLOSED", client_ip, f"Device: {device_id}")

@app.get("/")
async def root(request: Request):
    destination = "/web/" if operator_auth.session_key(request.cookies.get(COOKIE_NAME)) else "/login"
    return RedirectResponse(destination, status_code=303)
