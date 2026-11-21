#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from RsaCtfTool.attacks.abstract_attack import AbstractAttack
from RsaCtfTool.lib.number_theory import gcd
from RsaCtfTool.lib.utils import s2n
from RsaCtfTool.lib.keys_wrapper import PrivateKey


class Attack(AbstractAttack):
    def __init__(self, timeout=60):
        super().__init__(timeout)
        self.speed = AbstractAttack.speed_enum["medium"]

    def comfact(self, cipher, publickey):
        for c in cipher:
            commonfactor = gcd(publickey.n, s2n(c))

            # commonfactor == n means c == 0 (mod n): the "split" (1, n)
            # is not a factorization and must not touch publickey.p/q.
            if 1 < commonfactor < publickey.n:
                publickey.q = commonfactor
                publickey.p = publickey.n // publickey.q
                priv_key = PrivateKey(
                    int(publickey.p),
                    int(publickey.q),
                    int(publickey.e),
                    int(publickey.n),
                )
                return (priv_key, None)
        return (None, None)

    def attack(self, publickey, cipher=[], progress=True):
        """Try an attack where the public key has a common factor with the ciphertext - sourcekris"""
        return self.comfact(cipher, publickey) if cipher is not None else (None, None)

    def test(self):
        from RsaCtfTool.lib.keys_wrapper import PublicKey

        key_data = """-----BEGIN PUBLIC KEY-----
MFswDQYJKoZIhvcNAQEBBQADSgAwRwJAYxmYOA1V/wFffgnwCAjSLWjE4irnfdwp
mg0J9pXMLzqiItNvbHSdtI7l9/73nPt/9Rf+H+YN7bq3CGxmoYSMMQIDAQAB
-----END PUBLIC KEY-----"""

        p = 61428984774565994706291272379929830963007270789353687756549059578695208771059
        # Ciphertext sharing the factor p with n: gcd(n, c) = p.
        c = p * 12345
        cipher = [c.to_bytes((c.bit_length() + 7) // 8, "big")]

        priv_key, _ = self.attack(PublicKey(key_data), cipher, progress=False)
        return priv_key is not None and int(priv_key.n) == int(priv_key.p) * int(
            priv_key.q
        )
