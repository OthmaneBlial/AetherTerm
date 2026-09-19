# AetherTerm

An early prototype that relays a shell on an agent machine to a browser through a FastAPI WebSocket server. It is **not ready for network deployment**.

> **Security warning:** operator sign-in and per-device agent credentials are implemented. The documented local run uses plain `ws://`; a TLS option has only been checked locally with a temporary certificate. Keep the server bound to loopback while the [security roadmap](ROADMAP.md) is implemented. Do not use this revision for production administration or expose it to a LAN or the Internet.

## What exists today

- A Python FastAPI server with browser (`/ws`) and agent (`/client`) WebSocket endpoints.
- A Python agent that creates a `/bin/bash` PTY on request.
- An operator password login and a bundled xterm.js console that lists enrolled devices and opens interactive shells. Sessions are tied to the browser WebSocket that opened them.
- Device-bound agent credentials stored in owner-readable files, with server-side rotation and revocation.
- Agent reconnection attempts after connection failures, plus isolated PTYs for simultaneous local sessions. Existing shells close after disconnection; a returning agent needs a new session.

The browser terminal uses locally bundled xterm.js. Unicode, ANSI colors, `less`, Ctrl+C and resize have been exercised on macOS in Chrome; the full terminal interaction set and Linux behavior still need validation. The page derives its WebSocket URL from the page origin, but remote HTTPS/WSS deployment has not been validated outside a local proxy test. Operator and agent credentials are created outside the repository; no working defaults are shipped.

## Loopback-only development run

This flow was exercised on macOS with Python 3.13. It is a local prototype run, not a supported release or a Linux compatibility claim. From the project root:

```bash
python3.13 -m venv .venv
source .venv/bin/activate
python -m pip install .
aetherterm-admin init
aetherterm-admin enroll local-agent --output ~/.config/aetherterm/local-agent.token
```

The operator setup prompts for a password of at least 12 characters. Keep the generated credential file private. Add `--description "My Linux host"` to `enroll` if you want a label in the console. Enrolled devices stay visible when offline; their “last seen” time is remembered only while this server process runs.

In a second terminal, start the server:

```bash
source .venv/bin/activate
aetherterm-server --port 8001
```

In a third terminal, run the agent under the OS account whose shell you intend to use:

```bash
source .venv/bin/activate
aetherterm-agent --host 127.0.0.1 --port 8001 --device-id local-agent --token-file ~/.config/aetherterm/local-agent.token
```

Open `http://127.0.0.1:8001/web/` and sign in. Use `aetherterm-admin rotate local-agent --output <new-private-file>` to replace a device credential, or `aetherterm-admin revoke local-agent` to disable it. These commands change the server registry; restart the agent with the new file after rotation. Do not put credential files in Git or pass their contents through command arguments. The proposed remote TLS topology and its current evidence are in [the deployment guide](docs/DEPLOYMENT.md).

The terminal UI is bundled locally; no CDN connection is needed. To rebuild it after changing `web/src/`, run `cd web && npm ci && npm run build`. The checked-in `web/assets/` files let the Python quickstart work without Node. xterm.js and its fit addon are MIT licensed; their notices are in `web/licenses/`.

The agent reconnects automatically after a temporary server outage with bounded backoff. Existing shells close when either side disconnects; open a new session after reconnection. An invalid agent credential or rejected WSS certificate stops the agent so the operator can correct the configuration.

## Intended product

The proposed first release is a self-hosted console for one operator and multiple explicitly enrolled Linux agents. Browser sign-in, per-browser session ownership and device credentials have local integration tests. Verified HTTPS/WSS for remote access is still required. The intended scope and trust boundaries are in [the product contract](docs/PRODUCT.md) and [the threat model](docs/THREAT_MODEL.md). Those documents describe the complete release contract, not a claim that it has been delivered.

AetherTerm does not speak SSH. Compatibility, security and ease-of-use comparisons with other projects have not been measured yet. The [roadmap](ROADMAP.md) defines the work and evidence required before a release and before a real product demonstration video.

## Development status

| Area | Current evidence | Release requirement |
| --- | --- | --- |
| Shell relay | Two independent local PTYs, explicit close, browser disconnect and agent SIGTERM have integration tests on macOS. Chrome manually showed Unicode, ANSI colors, `less`, Ctrl+C and resize. | Linux validation, remaining terminal interactions and further interruption tests. |
| Browser access | Password login, cookie session, same-origin WebSocket and negative cross-browser integration test. | Full device authorization, expiry/revocation and deployment validation. |
| Agent identity | Per-device credential-file enrollment, rotation and revocation tested locally. | Remote encrypted transport, Linux installation and operating guidance. |
| Transport | Remote cleartext refused in code; direct TLS and a local Caddy HTTPS/WSS proxy test with certificate validation passed. | Public certificate, external network and graphical browser validation. |
| Packaging and automation | A local wheel installed in a clean macOS Python 3.13 venv served its bundled UI and completed a real authorized PTY round trip; local `unittest` integration tests exist. No CI or published release artifacts are verified. | Linux and other declared environments, automated gates and tested downloads. |

The MIT license is in [LICENSE](LICENSE). Contributions are welcome once the security and test setup are documented; please avoid deploying this revision to a reachable network. The complete sequence is tracked in [ROADMAP.md](ROADMAP.md).
