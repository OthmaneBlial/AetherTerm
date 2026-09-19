# Contributing

AetherTerm is a pre-release tool that grants shell access. Small, reviewable changes with reproducible evidence are welcome. Check [ROADMAP.md](ROADMAP.md) for open work and [SECURITY.md](SECURITY.md) before reporting an access-control issue. Do not include a working exploit, real credential, private hostname or terminal output from another person in a public issue or pull request.

## Local development

Use Python 3.13 in a virtual environment and Node.js 22 for the Web bundle. The CI runner is Ubuntu 24.04. On a fresh checkout:

```bash
python3.13 -m venv .venv
source .venv/bin/activate
python -m pip install --require-hashes -r requirements.lock
python -m pip install --no-deps .
ruff check server client tests scripts
mypy server client
python scripts/check_docs.py
python -m unittest discover -s tests -q
cd web
npm ci
npm run check
npm run build
cd ..
git diff --exit-code -- web/assets
```

The integration suite starts temporary server and agent processes on loopback, creates disposable credentials outside the repository, and exercises real PTYs. It does not require a public server. The browser journey also runs in Linux CI with Chromium; `scripts/verify_browser.py` needs Playwright and its Chromium runtime if run manually. Keep test credentials in temporary files, never in Git.

`requirements.lock` pins and hashes the Python 3.13 development dependencies; `requirements-runtime.lock` does the same for installed server and agent dependencies. They were generated with pip-tools 7.6.1 using `pip-compile --extra dev --strip-extras --generate-hashes` and `pip-compile --strip-extras --generate-hashes` respectively. Refresh both when dependency constraints change, review the entire diff, and confirm clean installs on the declared CI platform before merging.

For a manual first shell, follow [docs/QUICKSTART.md](docs/QUICKSTART.md). The [architecture](docs/ARCHITECTURE.md), [threat model](docs/THREAT_MODEL.md) and [operations guide](docs/OPERATIONS.md) explain the current contracts. Remote deployment claims require the separate checks in [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md).

## Pull requests and issues

Open an issue that describes the observed version or commit, OS, reproduction steps and expected behavior. For a UI problem, include a screenshot only after removing credentials and private host details. For a change to access, protocol or PTY handling, include a negative regression test and explain how existing sessions are affected. Keep source and generated `web/assets/` in sync; do not edit the bundled output alone.

Run the relevant local checks and report what remains unverified. CI tests Python, the installed wheel, Web assets, dependency scans and a real Chromium shell journey. A green run is evidence for those checks only. Do not claim production readiness, external network security or device support from it.

Useful small contributions include clearer error messages, accessible keyboard behavior, documentation corrections tied to a reproduced command, and focused tests for terminal programs or reconnect timing. Confirm that an issue is still open before investing substantial work. The roadmap lists work in dependency order; the final video phase must wait until every earlier gate is complete.
