# 🚀 AetherTerm - Remote Terminal Solution

**A lightweight, modern, and secure remote terminal solution in Python**

[![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)](https://python.org) [![WebSocket](https://img.shields.io/badge/WebSocket-Real--time-green.svg)](https://websockets.readthedocs.io/) [![FastAPI](https://img.shields.io/badge/FastAPI-Modern-orange.svg)](https://fastapi.tiangolo.com/)

## ✨ What is AetherTerm?

AetherTerm is a **complete remote terminal solution** that lets you access and control Linux terminals from any web browser. It's perfect for:

- 🖥️ **Remote server management**
- 📱 **Mobile terminal access**
- 🔧 **Embedded device control**
- 🌐 **Web-based SSH replacement**

## 🎯 Key Features

- ✅ **Browser-Based Terminal** - Access from any modern web browser
- ✅ **Real-time Communication** - WebSocket-powered low-latency connection
- ✅ **Multi-Device Support** - Connect to multiple remote devices
- ✅ **Auto-Reconnect** - Automatic reconnection on network issues
- ✅ **Clean Output** - ANSI escape code stripping for readable text
- ✅ **Modern UI** - Beautiful dark theme with smooth animations
- ✅ **Mobile Friendly** - Responsive design works on phones/tablets
- ✅ **Minimal Dependencies** - Lightweight and easy to deploy

## 🏗️ Architecture

```
┌─────────────────┐    WebSocket    ┌─────────────────┐    PTY    ┌─────────────────┐
│   Web Browser   │◄──────────────►│  AetherTerm     │◄─────────►│  Remote Linux   │
│   (Chrome/Firefox)│  /ws          │  Server (Port   │  /client   │  Device         │
│                 │                │  8001)         │            │                 │
└─────────────────┘                └─────────────────┘            └─────────────────┘
```

## 🚀 Quick Start (5 Minutes Setup)

### Prerequisites

- 🐍 **Python 3.8+**
- 📦 **pip** (Python package manager)

### Step 1: Download & Setup

```bash
# Clone or download the project
cd /path/to/your/projects

# Navigate to the project
cd aetherterm

# Install server dependencies
cd server
pip install -r requirements.txt

# Install client dependencies
cd ../client
pip install -r requirements.txt

# Go back to project root
cd ..
```

### Step 2: Start the Server

```bash
# From project root directory
python3 -m uvicorn server.main:app --host 0.0.0.0 --port 8001 --reload
```

**Expected Output:**

```
INFO:     Uvicorn running on http://0.0.0.0:8001 (Press CTRL+C to quit)
INFO:     Application startup complete.
```

### Step 3: Start a Client

```bash
# Open new terminal, from project root
python3 client/main.py --host localhost --port 8001 --device-id mypc --token secret123
```

**Expected Output:**

```
Registered successfully
Terminal started
```

### Step 4: Access Web Interface

**Open your browser and go to:** `http://localhost:8001/web/`

## 🎮 How to Use

1. **Click "🔍 List Devices"** - See all connected remote devices
2. **Click on "🖥️ mypc"** - Start terminal session
3. **Type commands** in the input field:
   - `ls` - List files
   - `pwd` - Show current directory
   - `whoami` - Show username
   - `ps` - Show running processes
   - Any Linux command!

## 📱 Mobile/Phone Access

**Test from your phone on the same WiFi:**

1. **Find your computer's IP:**

   ```bash
   ip addr show | grep "inet " | grep -v 127.0.0.1
   ```

   Example: `10.124.248.226`

2. **Start server with your IP:**

   ```bash
   python3 -m uvicorn server.main:app --host 10.124.248.226 --port 8001 --reload
   ```

3. **Start client:**

   ```bash
   python3 client/main.py --host 10.124.248.226 --port 8001 --device-id mobile-test --token abc123
   ```

4. **On your phone:** Open `http://10.124.248.226:8001/web/`

## 🔧 Configuration Options

### Server Options

```bash
# Change port
python3 -m uvicorn server.main:app --host 0.0.0.0 --port 9000

# Production mode (no reload)
python3 -m uvicorn server.main:app --host 0.0.0.0 --port 8001
```

### Client Options

```bash
python3 client/main.py \
  --host localhost \
  --port 8001 \
  --device-id my-server \
  --token my-secret-token \
  --description "Production Server"
```

## 🧪 Testing Multiple Devices

```bash
# Terminal 1: Device 1
python3 client/main.py --host localhost --port 8001 --device-id server1 --token token1

# Terminal 2: Device 2
python3 client/main.py --host localhost --port 8001 --device-id server2 --token token2

# Terminal 3: Device 3
python3 client/main.py --host localhost --port 8001 --device-id raspberry-pi --token token3
```

All devices will appear in the web interface!

## 📁 Project Structure

```
aetherterm/
├── 📁 server/              # FastAPI WebSocket server
│   ├── main.py            # Server application
│   ├── requirements.txt   # Server dependencies
│   └── __init__.py
├── 📁 client/              # PTY terminal client
│   ├── main.py            # Client application
│   ├── requirements.txt   # Client dependencies
│   └── __init__.py
├── 📁 web/                 # Web interface
│   └── index.html         # Vue.js terminal UI
├── 📄 README.md           # This file
└── 📁 docs/               # Documentation
```

## 🔒 Security Features

- **Token Authentication** - Secure client-server connection with validated tokens
- **Rate Limiting** - Protection against brute force and DoS attacks (10/min, 50/hour per IP)
- **IP-based Monitoring** - All connections logged with client IP addresses
- **Session Validation** - Invalid sessions are rejected and logged
- **Connection Limits** - Prevents device ID conflicts and unauthorized access
- **Security Event Logging** - Comprehensive logging of all security events
- **WebSocket Encryption** - Built-in security for data transmission
- **TLS Ready** - Easy SSL certificate integration for production

### Security Configuration

**Allowed Tokens** (configured in `server/main.py`):

```python
ALLOWED_TOKENS = {
    "secret123": "default_client",
    "admin_token": "admin_client",
    "demo_token": "demo_client"
}
```

**Rate Limiting**:

- Max 10 connections per minute per IP
- Max 50 connections per hour per IP
- Automatic cleanup of old connection attempts

### Security Logs

The server logs all security events with timestamps:

```
[SECURITY] 2025-01-09 15:18:29 - CLIENT_REGISTERED - IP: 192.168.1.100 - Device: mypc
[SECURITY] 2025-01-09 15:18:30 - SESSION_STARTED - IP: 192.168.1.100 - Session: abc-123
[SECURITY] 2025-01-09 15:18:45 - INVALID_TOKEN - IP: 10.0.0.5 - Device: hacker
```

## 🚀 Production Deployment

### Server Deployment

```bash
# Using systemd
sudo nano /etc/systemd/system/aetherterm.service

# Add this content:
[Unit]
Description=AetherTerm Server
After=network.target

[Service]
Type=simple
User=your-user
WorkingDirectory=/path/to/aetherterm
ExecStart=/usr/bin/python3 -m uvicorn server.main:app --host 0.0.0.0 --port 8001
Restart=always

[Install]
WantedBy=multi-user.target

# Enable and start
sudo systemctl enable aetherterm
sudo systemctl start aetherterm
```

### Client as Service

```bash
# Create client service
sudo nano /etc/systemd/system/aetherterm-client.service

# Add this content:
[Unit]
Description=AetherTerm Client
After=network.target

[Service]
Type=simple
User=your-user
WorkingDirectory=/path/to/aetherterm
ExecStart=/usr/bin/python3 client/main.py --host your-server-ip --port 8001 --device-id device-name --token your-token
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

## 🐛 Troubleshooting

### "Directory 'web' does not exist"

```bash
# Make sure you're running from project root
cd /path/to/aetherterm
python3 -m uvicorn server.main:app --host 0.0.0.0 --port 8001
```

### "Connection failed"

- Check if server is running: `netstat -tlnp | grep 8001`
- Verify port is not blocked by firewall
- Try different port if 8001 is in use

### "WebSocket error"

- Check browser console for JavaScript errors
- Verify WebSocket URL is correct: `ws://localhost:8001/ws`

### Weird characters in terminal

- This is normal - they're ANSI escape codes for colors
- The web interface automatically strips them for clean display

## 🤝 Contributing

We welcome contributions! Please:

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test thoroughly
5. Submit a pull request

## 📄 License

This project is open-source and available under the MIT License.

## 🙏 Acknowledgments

- Built with [FastAPI](https://fastapi.tiangolo.com/) - Modern Python web framework
- Real-time communication via [WebSockets](https://websockets.readthedocs.io/)
- Terminal emulation inspired by modern remote access tools

---

**🎉 Happy Terminal Remoting!**

If you have questions or need help, feel free to open an issue or start a discussion.
