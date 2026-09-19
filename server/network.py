"""Fail closed for remote cleartext access to the shell control plane."""

import ipaddress


def is_loopback(address: str) -> bool:
    try:
        return ipaddress.ip_address(address).is_loopback
    except ValueError:
        return False


def transport_allowed(scheme: str, client_address: str) -> bool:
    if scheme in ("https", "wss"):
        return True
    return scheme in ("http", "ws") and is_loopback(client_address)
