"""Download and SHA-256 check the official Circom Windows release.

urllib honors the normal local HTTPS proxy settings, unlike Node's fetch on
some Windows installations. No proxy configuration or TLS settings are changed.
"""
from __future__ import annotations
import hashlib
from pathlib import Path
import urllib.request

ROOT = Path(__file__).resolve().parent
TARGET = ROOT / "cache" / "circom-2.2.3.exe"
EXPECTED = "e43f132ee6f0aa79b705beceb59c2a7e6a54d7bdeab917ca34e9fc1951d185e1"


def main() -> None:
    if TARGET.exists():
        if hashlib.sha256(TARGET.read_bytes()).hexdigest() != EXPECTED:
            raise RuntimeError("Native compiler checksum mismatch")
        return
    request = urllib.request.Request("https://github.com/iden3/circom/releases/download/v2.2.3/circom-windows-amd64.exe")
    with urllib.request.urlopen(request, timeout=60) as response:
        binary = response.read()
    if hashlib.sha256(binary).hexdigest() != EXPECTED:
        raise RuntimeError("Downloaded native compiler checksum mismatch")
    TARGET.parent.mkdir(exist_ok=True)
    TARGET.write_bytes(binary)
    print("Official Circom 2.2.3 downloaded and SHA-256 verified", flush=True)


if __name__ == "__main__":
    main()
