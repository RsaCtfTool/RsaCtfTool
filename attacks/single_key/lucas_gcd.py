#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from attacks.abstract_attack import AbstractAttack
from tqdm import tqdm
from lib.keys_wrapper import PrivateKey
from lib.number_theory import gcd, lucas


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
        if p is not None and q is not None:
            priv_key = PrivateKey(int(p), int(q), int(publickey.e), int(publickey.n))
            return priv_key, None
        return None, None

    def test(self):
        from lib.keys_wrapper import PublicKey

        key_data = """-----BEGIN PUBLIC KEY-----
MHEwDQYJKoZIhvcNAQEBBQADYAAwXQJWHQ0rgHPOeBLv8krCj1istQHg9WiGipFC
yRgxnJmStyO4wM8pQv1Y7FjpJVFILVqxP4KbUCB1gH9A3oz3UwaRlDB0S23Hv4NX
DiaTiwgPiVBEVKuQJ7sCAwEAAQ==
-----END PUBLIC KEY-----"""
        result = self.attack(PublicKey(key_data), progress=False)
        return result != (None, None)
