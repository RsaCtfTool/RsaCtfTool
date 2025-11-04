#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from tqdm import tqdm
from RsaCtfTool.attacks.abstract_attack import AbstractAttack
from RsaCtfTool.lib.number_theory import gcd, lucas


class Attack(AbstractAttack):
    def __init__(self, timeout=60):
        super().__init__(timeout)
        self.speed = AbstractAttack.speed_enum["fast"]

    def attack(self, publickey, cipher=[], progress=True):
        """Run tests against Lucas numbers"""
        limit = 10000
        p = q = None
        for x in tqdm(range(1, limit), disable=(not progress)):
            f = gcd(lucas(x), publickey.n)
            if 1 < f < publickey.n:
                p = publickey.n // f
                q = f
                break
        return self.create_private_key_from_pqe(p, q, publickey.e, publickey.n)

    def test(self):
        from RsaCtfTool.lib.keys_wrapper import PublicKey

        key_data = """-----BEGIN PUBLIC KEY-----
MHEwDQYJKoZIhvcNAQEBBQADYAAwXQJWHQ0rgHPOeBLv8krCj1istQHg9WiGipFC
yRgxnJmStyO4wM8pQv1Y7FjpJVFILVqxP4KbUCB1gH9A3oz3UwaRlDB0S23Hv4NX
DiaTiwgPiVBEVKuQJ7sCAwEAAQ==
-----END PUBLIC KEY-----"""
        result = self.attack(PublicKey(key_data), progress=False)
        return result != (None, None)
