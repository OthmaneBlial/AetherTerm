# AetherTerm

An early prototype that relays a shell on an agent machine to a browser through a FastAPI WebSocket server. It is **not ready for network deployment**.

> **Security warning:** operator sign-in now guards the browser WebSocket, but agent tokens embedded in the source are public and the current transport is plain `ws://`. Keep the server bound to loopback while the [security roadmap](ROADMAP.md) is implemented. Do not use this revision for production administration or expose it to a LAN or the Internet.

## What exists today

- A Python FastAPI server with browser (`/ws`) and agent (`/client`) WebSocket endpoints.
- A Python agent that creates a `/bin/bash` PTY on request.
- An operator password login and a single HTML/Vue page that lists connected IDs, displays text output and sends command lines. Sessions are tied to the browser WebSocket that opened them.
- Agent reconnection attempts after connection failures. Browser reconnection and safe multi-session handling are not implemented.

The Web page is a text display, not a complete terminal emulator. ANSI sequences are stripped and Unicode handling is unreliable. The page now derives its WebSocket URL from the page origin, but remote HTTPS/WSS deployment has not been validated. The agent currently accepts only tokens embedded in `server/main.py`. Those values are not secrets and must be replaced before a usable quickstart can be documented. Operator setup is available through `python -m server.admin init`; keep the resulting private file outside the repository.

## Intended product

The proposed first release is a self-hosted console for one operator and multiple explicitly enrolled Linux agents. Browser sign-in and per-browser session ownership have local integration tests. Device-bound agent credentials and verified HTTPS/WSS for remote access are still required. The intended scope and trust boundaries are in [the product contract](docs/PRODUCT.md) and [the threat model](docs/THREAT_MODEL.md). Those documents describe the complete release contract, not a claim that it has been delivered.

AetherTerm does not speak SSH. Compatibility, security and ease-of-use comparisons with other projects have not been measured yet. The [roadmap](ROADMAP.md) defines the work and evidence required before a release and before a real product demonstration video.

## Development status

| Area | Current evidence | Release requirement |
| --- | --- | --- |
| Shell relay | Local server/agent WebSocket round trip was exercised during the roadmap audit. | Independent PTYs, cleanup, full terminal interactions and Linux validation. |
| Browser access | Password login, cookie session, same-origin WebSocket and negative cross-browser integration test. | Full device authorization, expiry/revocation and deployment validation. |
| Agent identity | Shared public tokens in source. | Per-device enrollment, rotation and revocation. |
| Transport | Plain `ws://` in agent and page. | Loopback-only plain mode and verified WSS for remote mode. |
| Packaging and automation | Requirements files only; no tests, CI or release artifacts in this checkout. | Reproducible installs, automated gates and tested downloads. |

The MIT license is in [LICENSE](LICENSE). Contributions are welcome once the security and test setup are documented; please avoid deploying this revision to a reachable network. The complete sequence is tracked in [ROADMAP.md](ROADMAP.md).
