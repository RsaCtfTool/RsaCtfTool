#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from tqdm import tqdm
from RsaCtfTool.attacks.abstract_attack import AbstractAttack
from RsaCtfTool.lib.number_theory import gcd


class Attack(AbstractAttack):
    def __init__(self, timeout=60):
        super().__init__(timeout)
        self.speed = AbstractAttack.speed_enum["medium"]

    def attack(self, publickey, cipher=[], progress=True):
        """Run tests against factorial +-1 composites"""
        limit = 30000
        p = q = None
        f = 1
        for x in tqdm(range(2, limit), disable=(not progress)):
            # f  = fac(x)
            f *= x
            g = gcd(f - 1, publickey.n)
            if 1 < g < publickey.n:
                p = publickey.n // g
                q = g
                break
            g = gcd(f + 1, publickey.n)
            if 1 < g < publickey.n:
                p = publickey.n // g
                q = g
                break
        return self.create_private_key_from_pqe(p, q, publickey.e, publickey.n)

    def test(self):
        from RsaCtfTool.lib.keys_wrapper import PublicKey

        key_data = """-----BEGIN PUBLIC KEY-----
MCcwDQYJKoZIhvcNAQEBBQADFgAwEwIMBzd7j1U0b2YJk4yPAgMBAAE=
-----END PUBLIC KEY-----"""
        result = self.attack(PublicKey(key_data), progress=False)
        return result != (None, None)
