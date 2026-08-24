"""Container integrity and authentication tags."""

from __future__ import annotations

import hashlib

from .crypto import mac, mac_verify


def checksum(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def compute_tag(mac_key: bytes, covered: bytes) -> bytes:
    return mac(mac_key, covered)


def verify_tag(mac_key: bytes, covered: bytes, tag: bytes) -> bool:
    return mac_verify(mac_key, covered, tag)
