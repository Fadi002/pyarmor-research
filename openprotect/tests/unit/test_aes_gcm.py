import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "src"))

from openprotect.protection.aes import Aes
from openprotect.protection.gcm import AesGcm


def h(s: str) -> bytes:
    return bytes.fromhex(s)


class AesKAT(unittest.TestCase):
    """FIPS-197 known-answer vectors."""

    def test_aes128(self):
        aes = Aes(h("000102030405060708090a0b0c0d0e0f"))
        ct = aes.encrypt_block(h("00112233445566778899aabbccddeeff"))
        self.assertEqual(ct.hex(), "69c4e0d86a7b0430d8cdb78070b4c55a")

    def test_aes256(self):
        aes = Aes(h("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"))
        ct = aes.encrypt_block(h("00112233445566778899aabbccddeeff"))
        self.assertEqual(ct.hex(), "8ea2b7ca516745bfeafc49904b496089")


class GcmKAT(unittest.TestCase):
    """NIST GCM spec test vectors."""

    def test_aes128_empty(self):
        g = AesGcm(b"\x00" * 16)
        ct, tag = g.seal(b"\x00" * 12, b"", b"")
        self.assertEqual(ct, b"")
        self.assertEqual(tag.hex(), "58e2fccefa7e3061367f1d57a4e7455a")

    def test_aes128_one_block(self):
        g = AesGcm(b"\x00" * 16)
        ct, tag = g.seal(b"\x00" * 12, b"\x00" * 16)
        self.assertEqual(ct.hex(), "0388dace60b6a392f328c2b971b2fe78")
        self.assertEqual(tag.hex(), "ab6e47d42cec13bdf53a67b21257bddf")

    def test_multi_block_roundtrip_and_determinism(self):
        """Cross-validated once against the `cryptography` package
        (AESGCM, 43.0.3) on random inputs; KATs above pin correctness."""
        key = h("feffe9928665731c6d6a8f9467308308")
        iv = h("cafebabefacedbaddecaf888")
        aad = h("feedfacedeadbeeffeedfacedeadbeefabaddad2")
        pt = bytes(range(64)) * 2
        g = AesGcm(key)
        ct1, tag1 = g.seal(iv, pt, aad)
        ct2, tag2 = g.seal(iv, pt, aad)
        self.assertEqual((ct1, tag1), (ct2, tag2))
        self.assertEqual(g.open(iv, ct1, tag1, aad), pt)
        self.assertNotEqual(ct1[:16], ct1[16:32])

    def test_aes256_vectors(self):
        g = AesGcm(b"\x00" * 32)
        _ct, tag = g.seal(b"\x00" * 12, b"", b"")
        self.assertEqual(tag.hex(), "530f8afbc74536b9a963b4f1c4cb738b")

        g2 = AesGcm(b"\x00" * 32)
        ct, tag2 = g2.seal(b"\x00" * 12, b"\x00" * 16)
        self.assertEqual(ct.hex(), "cea7403d4d606b6e074ec5d3baf39d18")
        self.assertEqual(tag2.hex(), "d0d1c8a799996bf0265b98b5d48ab919")

    def test_roundtrip_random(self):
        key = os.urandom(32)
        iv = os.urandom(12)
        msg = os.urandom(1000)
        aad = os.urandom(33)
        g = AesGcm(key)
        ct, tag = g.seal(iv, msg, aad)
        self.assertEqual(g.open(iv, ct, tag, aad), msg)

    def test_tamper_detected(self):
        g = AesGcm(os.urandom(32))
        iv = os.urandom(12)
        ct, tag = g.seal(iv, b"x" * 100, b"aad")
        bad = bytearray(ct)
        bad[50] ^= 1
        with self.assertRaises(ValueError):
            g.open(iv, bytes(bad), tag, b"aad")


if __name__ == "__main__":
    unittest.main()
