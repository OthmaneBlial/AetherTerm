"""Safe loopback-only server entry point for installed packages."""

import argparse

import uvicorn


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the AetherTerm server on loopback")
    parser.add_argument("--port", type=int, default=8001)
    args = parser.parse_args()
    if not 1 <= args.port <= 65535:
        parser.error("Port must be between 1 and 65535")
    uvicorn.run("server.main:app", host="127.0.0.1", port=args.port,
                proxy_headers=True, forwarded_allow_ips="127.0.0.1", workers=1)


if __name__ == "__main__":
    main()
