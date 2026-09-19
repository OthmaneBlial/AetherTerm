# AetherTerm

An early prototype that relays a shell on an agent machine to a browser through a FastAPI WebSocket server. It is **not ready for network deployment**.

> **Security warning:** operator sign-in and per-device agent credentials are implemented, but the current transport is plain `ws://`. Keep the server bound to loopback while the [security roadmap](ROADMAP.md) is implemented. Do not use this revision for production administration or expose it to a LAN or the Internet.

## What exists today

- A Python FastAPI server with browser (`/ws`) and agent (`/client`) WebSocket endpoints.
- A Python agent that creates a `/bin/bash` PTY on request.
- An operator password login and a single HTML/Vue page that lists connected IDs, displays text output and sends command lines. Sessions are tied to the browser WebSocket that opened them.
- Device-bound agent credentials stored in owner-readable files, with server-side rotation and revocation.
- Agent reconnection attempts after connection failures. Browser reconnection and safe multi-session handling are not implemented.

The Web page is a text display, not a complete terminal emulator. ANSI sequences are stripped and Unicode handling is unreliable. The page derives its WebSocket URL from the page origin, but remote HTTPS/WSS deployment has not been validated. Operator and agent credentials are created outside the repository; no working defaults are shipped.

## Loopback-only development run

This flow was exercised on macOS with Python 3.13. It is a local prototype run, not a supported release or a Linux compatibility claim. From the project root:

```bash
python3.13 -m venv .venv
source .venv/bin/activate
python -m pip install -r server/requirements.txt -r client/requirements.txt
python -m server.admin init
python -m server.admin enroll local-agent --output ~/.config/aetherterm/local-agent.token
```

The operator setup prompts for a password of at least 12 characters. Keep the generated credential file private. In a second terminal, start the server:

```bash
source .venv/bin/activate
python -m uvicorn server.main:app --host 127.0.0.1 --port 8001
```

In a third terminal, run the agent under the OS account whose shell you intend to use:

```bash
source .venv/bin/activate
python client/main.py --host 127.0.0.1 --port 8001 --device-id local-agent --token-file ~/.config/aetherterm/local-agent.token
```

Open `http://127.0.0.1:8001/web/` and sign in. Use `python -m server.admin rotate local-agent --output <new-private-file>` to replace a device credential, or `python -m server.admin revoke local-agent` to disable it. These commands change the server registry; restart the agent with the new file after rotation. Do not put credential files in Git or pass their contents through command arguments.

## Intended product

The proposed first release is a self-hosted console for one operator and multiple explicitly enrolled Linux agents. Browser sign-in, per-browser session ownership and device credentials have local integration tests. Verified HTTPS/WSS for remote access is still required. The intended scope and trust boundaries are in [the product contract](docs/PRODUCT.md) and [the threat model](docs/THREAT_MODEL.md). Those documents describe the complete release contract, not a claim that it has been delivered.

AetherTerm does not speak SSH. Compatibility, security and ease-of-use comparisons with other projects have not been measured yet. The [roadmap](ROADMAP.md) defines the work and evidence required before a release and before a real product demonstration video.

## Development status

| Area | Current evidence | Release requirement |
| --- | --- | --- |
| Shell relay | Local server/agent WebSocket round trip was exercised during the roadmap audit. | Independent PTYs, cleanup, full terminal interactions and Linux validation. |
| Browser access | Password login, cookie session, same-origin WebSocket and negative cross-browser integration test. | Full device authorization, expiry/revocation and deployment validation. |
| Agent identity | Per-device credential-file enrollment, rotation and revocation tested locally. | Remote encrypted transport, Linux installation and operating guidance. |
| Transport | Plain `ws://` in agent and page. | Loopback-only plain mode and verified WSS for remote mode. |
| Packaging and automation | Requirements files and local `unittest` integration tests; no CI or release artifacts in this checkout. | Reproducible installs, automated gates and tested downloads. |

The MIT license is in [LICENSE](LICENSE). Contributions are welcome once the security and test setup are documented; please avoid deploying this revision to a reachable network. The complete sequence is tracked in [ROADMAP.md](ROADMAP.md).
