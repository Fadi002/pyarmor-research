import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "src"))

from openprotect.protection import container, keys


def make_container(undo: bool):
    outer = keys.generate_outer_key("k")
    nonce = b"\x05" * 12
    inner = keys.derive_inner_keys(outer, nonce)
    header = {"module": "m", "pytag": "3.13.0"}
    blob = container.pack(
        header,
        b"payload-bytes",
        b"undo-data" if undo else None,
        nonce,
        inner["enc"],
        inner["undo"],
    )
    return blob, outer, nonce


class ContainerTests(unittest.TestCase):
    def _keys(self, outer, nonce):
        return keys.derive_inner_keys(outer, nonce)

    def test_roundtrip_no_undo(self):
        blob, outer, nonce = make_container(False)
        k = self._keys(outer, nonce)
        hdr, payload, undo = container.unpack(blob, k["enc"], k["undo"])
        self.assertEqual(payload, b"payload-bytes")
        self.assertIsNone(undo)
        self.assertEqual(hdr["module"], "m")
        self.assertEqual(hdr["fmt"], container.FORMAT_VERSION)

    def test_roundtrip_with_undo(self):
        blob, outer, nonce = make_container(True)
        k = self._keys(outer, nonce)
        hdr, payload, undo = container.unpack(blob, k["enc"], k["undo"])
        self.assertEqual(payload, b"payload-bytes")
        self.assertEqual(undo, b"undo-data")

    def test_tamper_rejected(self):
        blob, outer, nonce = make_container(False)
        k = self._keys(outer, nonce)
        tampered = bytearray(blob)
        tampered[-20] ^= 0xFF
        with self.assertRaises(container.ContainerError):
            container.unpack(bytes(tampered), k["enc"], k["undo"])

    def test_payload_tamper_rejected(self):
        blob, outer, nonce = make_container(False)
        k = self._keys(outer, nonce)
        header_len = int.from_bytes(blob[10:12], "big")
        tampered = bytearray(blob)
        tampered[12 + header_len + 3] ^= 0xFF
        with self.assertRaises(container.ContainerError):
            container.unpack(bytes(tampered), k["enc"], k["undo"])

    def test_wrong_key_rejected(self):
        blob, _outer, nonce = make_container(False)
        other = keys.derive_inner_keys(keys.generate_outer_key("z"), nonce)
        with self.assertRaises(container.ContainerError):
            container.unpack(blob, other["enc"], other["undo"])

    def test_bad_magic(self):
        with self.assertRaises(container.ContainerError):
            container.read_header_unverified(b"NOTMAGIC" + b"\x00" * 64)


if __name__ == "__main__":
    unittest.main()
