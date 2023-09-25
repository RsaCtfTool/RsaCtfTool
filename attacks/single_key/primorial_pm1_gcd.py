#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from attacks.abstract_attack import AbstractAttack
from tqdm import tqdm
from lib.keys_wrapper import PrivateKey
from lib.number_theory import gcd, next_prime


class Attack(AbstractAttack):
    def __init__(self, timeout=60):
        super().__init__(timeout)
        self.speed = AbstractAttack.speed_enum["medium"]

    def attack(self, publickey, cipher=[], progress=True):
        """Run tests against primorial +-1 composites"""
        limit = 10000
        prime = 1
        primorial = 1
        p = q = None
        for _ in tqdm(range(0, limit), disable=(not progress)):
            prime = next_prime(prime)
            primorial *= prime
            primorial_p1 = [primorial - 1, primorial + 1]
            g0, g1 = gcd(primorial_p1[0], publickey.n), gcd(
                primorial_p1[1], publickey.n
            )
            if 1 < g0 < publickey.n:
                p = publickey.n // g0
                q = g0
                break
            if 1 < g1 < publickey.n:
                p = publickey.n // g1
                q = g1
                break
        if p is not None and q is not None:
            priv_key = PrivateKey(int(p), int(q), int(publickey.e), int(publickey.n))
            return priv_key, None
        return None, None

    def test(self):
        from lib.keys_wrapper import PublicKey

        key_data = """-----BEGIN PUBLIC KEY-----
MGIwDQYJKoZIhvcNAQEBBQADUQAwTgJHRxjQFVPVvt1fa+cUt3fS5qNiHLa/OeaX
5USLac4dYG3GsvE97xPdzXfx6iQiM5u9608uoygqBRfr+YN4bTuvC6omcabKO30C
AwEAAQ==
-----END PUBLIC KEY-----"""
        result = self.attack(PublicKey(key_data), progress=False)
        return result != (None, None)
