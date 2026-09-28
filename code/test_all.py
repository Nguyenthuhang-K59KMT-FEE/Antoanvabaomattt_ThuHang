"""Chạy:  python -m unittest -v test_all"""
import os
import unittest

import my_aes as aes
import my_rsa as rsa

PT = bytes.fromhex("00112233445566778899aabbccddeeff")


class TestAES(unittest.TestCase):
    def test_sbox(self):
        self.assertEqual(aes.SBOX[0x00], 0x63)
        self.assertEqual(aes.SBOX[0x53], 0xED)

    def test_fips197_vectors(self):
        vectors = {
            16: "69c4e0d86a7b0430d8cdb78070b4c55a",
            24: "dda97ca4864cdfe06eaf70a0ec0d7191",
            32: "8ea2b7ca516745bfeafc49904b496089",
        }
        for n, expected in vectors.items():
            key = bytes(range(n))
            ct = aes.AES(key).encrypt_block(PT)
            self.assertEqual(ct.hex(), expected)
            self.assertEqual(aes.AES(key).decrypt_block(ct), PT)

    def test_cbc_roundtrip(self):
        for n in (16, 24, 32):
            key = os.urandom(n)
            for size in (0, 1, 15, 16, 17, 1000):
                data = os.urandom(size)
                self.assertEqual(aes.cbc_decrypt(key, aes.cbc_encrypt(key, data)), data)

    def test_wrong_key_fails(self):
        ct = aes.cbc_encrypt(b"k" * 16, b"hello world")
        with self.assertRaises(ValueError):
            aes.cbc_decrypt(b"x" * 16, ct)


class TestRSA(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.pub, cls.priv = rsa.generate_keypair(1024)

    def test_textbook_example(self):
        p, q, e = 61, 53, 17
        n, phi = p * q, (p - 1) * (q - 1)
        d = pow(e, -1, phi)
        self.assertEqual((n, phi, d), (3233, 3120, 2753))
        self.assertEqual(pow(65, e, n), 2790)
        self.assertEqual(pow(2790, d, n), 65)

    def test_key_properties(self):
        pub, priv = self.pub, self.priv
        self.assertEqual(priv.p * priv.q, pub.n)
        self.assertEqual((pub.e * priv.d) % ((priv.p - 1) * (priv.q - 1)), 1)

    def test_encrypt_decrypt(self):
        m = b"xin chao RSA"
        c = rsa.encrypt(self.pub, m)
        self.assertEqual(rsa.decrypt(self.priv, c), m)
        self.assertEqual(rsa.decrypt(self.priv, c, use_crt=False), m)

    def test_encryption_is_randomized(self):
        m = b"same"
        self.assertNotEqual(rsa.encrypt(self.pub, m), rsa.encrypt(self.pub, m))

    def test_sign_verify(self):
        s = rsa.sign(self.priv, b"hop dong")
        self.assertTrue(rsa.verify(self.pub, b"hop dong", s))
        self.assertFalse(rsa.verify(self.pub, b"hop dong 2", s))

    def test_wrong_key(self):
        other_pub, other_priv = rsa.generate_keypair(1024)
        s = rsa.sign(other_priv, b"x")
        self.assertFalse(rsa.verify(self.pub, b"x", s))

    def test_message_too_long(self):
        with self.assertRaises(ValueError):
            rsa.encrypt(self.pub, b"a" * 200)


if __name__ == "__main__":
    unittest.main()
