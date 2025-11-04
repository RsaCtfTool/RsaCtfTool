#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from tqdm import tqdm
from RsaCtfTool.attacks.abstract_attack import AbstractAttack
from RsaCtfTool.lib.number_theory import gcd, next_prime


class Attack(AbstractAttack):
    def __init__(self, timeout=60):
        super().__init__(timeout)
        self.speed = AbstractAttack.speed_enum["medium"]

    def attack(self, publickey, cipher=[], progress=True):
        """Run tests against factorial +-1 composites"""
        limit = 10001
        p = q = None
        F = 1
        p = 2

        for x in tqdm(range(2, limit), disable=(not progress)):
            F *= x
            while F % p == 0:
                F //= p
                p = next_prime(p)
            g = gcd(F - 1, publickey.n)
            if 1 < g < publickey.n:
                p = publickey.n // g
                q = g
                break
            g = gcd(F + 1, publickey.n)
            if 1 < g < publickey.n:
                p = publickey.n // g
                q = g
                break
        return self.create_private_key_from_pqe(p, q, publickey.e, publickey.n)

    def test(self):
        from RsaCtfTool.lib.keys_wrapper import PublicKey

        key_data = """-----BEGIN PUBLIC KEY-----
MHUwDQYJKoZIhvcNAQEBBQADZAAwYQJaATHFe5J2n1H2ehgo6XUD2H8f+a2zitXH
BAHGnIUU4v/Q2t6S2rnrsKRrtTNdbeI62VDLh/J0X8P6vBoX+xnfk9XYQ75bmC+x
uIBpvW2sySPVKj8G8/lNcxhxAgMBAAE=
-----END PUBLIC KEY-----"""
        result = self.attack(PublicKey(key_data), progress=False)
        return result != (None, None)
