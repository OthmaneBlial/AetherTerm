# Security reporting

AetherTerm is a pre-release shell access tool. Do not deploy the current revision on an untrusted network. The supported security model and its unverified boundaries are described in [docs/SECURITY.md](docs/SECURITY.md) and [ROADMAP.md](ROADMAP.md).

Please do not publish a working exploit, credential or private host detail in a GitHub issue. A dedicated private reporting channel has not yet been verified for this repository. Until it is available, open a brief issue without exploit details asking the maintainer for a private contact route. This is an interim process, not a promise of a response time or coordinated disclosure service.

Reports should include the affected commit or version, deployment mode (loopback or TLS proxy), reproduction steps that avoid real secrets, expected versus observed behavior, and potential impact. Never send a live credential.
