"""License descriptors: expiry, device binding, user data.

Mirrors the reference workflow's runtime-key concept with our own format:
a canonical-JSON descriptor is PSS-signed at protect time; the generated
runtime package carries the public key and refuses to load a container
whose descriptor fails signature or constraint checks.

Descriptor fields:
    exp    ISO date; container refuses to run after this day (UTC)
    dev    list of required device fingerprints; empty list = any machine.
           Entries are 'mac:<hex>' (MAC via uuid.getnode) or 'str:<value>'
           compared against OPENPROTECT_DEVICE env override, then MAC.
    data   opaque string surfaced to the app via __pyarmor_license__
    period accepted for CLI compatibility; v1 enforces checks at import
"""

from __future__ import annotations

import base64
import datetime as _dt
import hashlib
import json
import uuid

from . import rsa


def _canonical(desc: dict) -> bytes:
    return json.dumps(desc, sort_keys=True, separators=(",", ":")).encode("utf-8")


def build_descriptor(
    expired: str | None,
    bind_device: list[str] | None,
    bind_data: str | None,
    period: int | None,
) -> bytes:
    desc: dict = {}
    if expired:
        _dt.date.fromisoformat(expired)  # validate early
        desc["exp"] = expired
    if bind_device:
        desc["dev"] = [_normalize_device(d) for d in bind_device]
    if bind_data:
        desc["data"] = bind_data
    if period:
        desc["period"] = int(period)
    return _canonical(desc)


def _normalize_device(value: str) -> str:
    value = value.strip()
    if ":" in value and value.split(":", 1)[0] in ("mac", "str"):
        return value
    # bare value: treat hex-ish 12-char input as a MAC, else literal string
    compact = value.replace(":", "").replace("-", "").lower()
    if len(compact) == 12 and all(c in "0123456789abcdef" for c in compact):
        return f"mac:{compact}"
    return f"str:{value}"


def current_fingerprints() -> list[str]:
    fps = []
    node = uuid.getnode()
    mac = f"{node:012x}"
    if mac != "000000000000":  # getnode fallback marker
        fps.append(f"mac:{mac}")
    import os

    env = os.environ.get("OPENPROTECT_DEVICE")
    if env:
        fps.append(f"str:{env}")
    return fps


def sign_descriptor(key: dict, descriptor: bytes) -> tuple[str, str]:
    sig = rsa.sign(key, descriptor)
    return (
        base64.b64encode(descriptor).decode("ascii"),
        base64.b64encode(sig).decode("ascii"),
    )


def check_license(
    public_n: int,
    public_e: int,
    desc_b64: str,
    sig_b64: str,
) -> dict | None:
    """Verify + evaluate. Returns descriptor dict, or None when absent.

    Raises LicenseError on signature failure or violated constraints -
    the loader treats that as fail-closed.
    """
    if not desc_b64:
        return None
    descriptor = base64.b64decode(desc_b64)
    signature = base64.b64decode(sig_b64)
    if not rsa.verify((public_n, public_e), descriptor, signature):
        raise LicenseError("license signature verification failed")

    desc: dict = json.loads(descriptor.decode("utf-8"))

    if "exp" in desc:
        expiry = _dt.date.fromisoformat(desc["exp"])
        if _dt.datetime.now(_dt.timezone.utc).date() > expiry:
            raise LicenseError(f"license expired on {desc['exp']}")

    required: list[str] = desc.get("dev", [])
    if required:
        available = set(current_fingerprints())
        missing = [d for d in required if d not in available]
        if missing:
            raise LicenseError(f"device binding not satisfied: {missing}")

    return desc


class LicenseError(Exception):
    pass


def fingerprint_of(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()[:16]
