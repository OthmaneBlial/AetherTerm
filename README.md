# AetherTerm

An early prototype that relays a shell on an agent machine to a browser through a FastAPI WebSocket server. It is **not ready for network deployment**.

> **Security warning:** the current browser WebSocket has no authentication. Anyone who can reach the server can list connected agents and open a shell with the agent process's OS permissions. The example agent tokens in the source are public, and the current transport is plain `ws://`. Keep the server bound to loopback while the [security roadmap](ROADMAP.md) is implemented. Do not use this revision for production administration or expose it to a LAN or the Internet.

## What exists today

- A Python FastAPI server with browser (`/ws`) and agent (`/client`) WebSocket endpoints.
- A Python agent that creates a `/bin/bash` PTY on request.
- A single HTML/Vue page that lists connected IDs, displays text output and sends command lines.
- Agent reconnection attempts after connection failures. Browser reconnection and safe multi-session handling are not implemented.

The Web page is a text display, not a complete terminal emulator. ANSI sequences are stripped and Unicode handling is unreliable. The page hardcodes `ws://localhost:8001/ws`, so opening it from another host or on another port is not a supported workflow. The agent currently accepts only tokens embedded in `server/main.py`. Those values are not secrets and must be replaced before a usable quickstart can be documented.

## Intended product

The proposed first release is a self-hosted console for one operator and multiple explicitly enrolled Linux agents. It will require browser authentication, device-bound agent credentials, per-session ownership and verified HTTPS/WSS for remote access. The intended scope and trust boundaries are in [the product contract](docs/PRODUCT.md) and [the threat model](docs/THREAT_MODEL.md). These documents describe work to be implemented, not features already delivered.

AetherTerm does not speak SSH. Compatibility, security and ease-of-use comparisons with other projects have not been measured yet. The [roadmap](ROADMAP.md) defines the work and evidence required before a release and before a real product demonstration video.

## Development status

| Area | Current evidence | Release requirement |
| --- | --- | --- |
| Shell relay | Local server/agent WebSocket round trip was exercised during the roadmap audit. | Independent PTYs, cleanup, full terminal interactions and Linux validation. |
| Browser access | No browser authentication or session ownership checks. | Authenticated operator and negative cross-browser tests. |
| Agent identity | Shared public tokens in source. | Per-device enrollment, rotation and revocation. |
| Transport | Plain `ws://` in agent and page. | Loopback-only plain mode and verified WSS for remote mode. |
| Packaging and automation | Requirements files only; no tests, CI or release artifacts in this checkout. | Reproducible installs, automated gates and tested downloads. |

The MIT license is in [LICENSE](LICENSE). Contributions are welcome once the security and test setup are documented; please avoid deploying this revision to a reachable network. The complete sequence is tracked in [ROADMAP.md](ROADMAP.md).
