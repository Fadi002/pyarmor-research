import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "src"))

from openprotect.protection.crypto import decrypt, encrypt, mac, mac_verify
from openprotect.protection.keys import derive_inner_keys, generate_outer_key


class CryptoTests(unittest.TestCase):
    def test_roundtrip(self):
        key = generate_outer_key("seed")
        nonce = b"\x01" * 16
        msg = b"attack at dawn" * 100
        self.assertEqual(decrypt(key, nonce, encrypt(key, nonce, msg)), msg)

    def test_wrong_key_fails(self):
        key = generate_outer_key("seed")
        other = generate_outer_key("other")
        nonce = b"\x02" * 16
        ct = encrypt(key, nonce, b"secret")
        self.assertNotEqual(decrypt(other, nonce, ct), b"secret")

    def test_mac(self):
        k = generate_outer_key()
        tag = mac(k, b"data")
        self.assertTrue(mac_verify(k, b"data", tag))
        self.assertFalse(mac_verify(k, b"datb", tag))


class KeyTests(unittest.TestCase):
    def test_seed_deterministic(self):
        self.assertEqual(generate_outer_key("abc"), generate_outer_key("abc"))
        self.assertNotEqual(generate_outer_key("abc"), generate_outer_key("abd"))

    def test_unseeded_random(self):
        self.assertNotEqual(generate_outer_key(), generate_outer_key())

    def test_inner_derivation_contextual(self):
        outer = generate_outer_key("s")
        n1, n2 = b"\x03" * 16, b"\x04" * 16
        a = derive_inner_keys(outer, n1)
        b = derive_inner_keys(outer, b"\x0a" * 16)
        c = derive_inner_keys(outer, n2)
        self.assertNotEqual(a["enc"], b["enc"])
        self.assertNotEqual(a["enc"], c["enc"])
        again = derive_inner_keys(outer, n1)
        self.assertEqual(a, again)


if __name__ == "__main__":
    unittest.main()
