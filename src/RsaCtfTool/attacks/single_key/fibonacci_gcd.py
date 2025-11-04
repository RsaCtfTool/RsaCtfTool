#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from tqdm import tqdm
from RsaCtfTool.attacks.abstract_attack import AbstractAttack
from RsaCtfTool.lib.number_theory import gcd, fib


class Attack(AbstractAttack):
    def __init__(self, timeout=60):
        super().__init__(timeout)
        self.speed = AbstractAttack.speed_enum["fast"]

    def attack(self, publickey, cipher=[], progress=True):
        """Run tests against fermat composites"""
        limit = 10000
        p = q = None
        for x in tqdm(range(1, limit), disable=(not progress)):
            f = gcd(fib(x), publickey.n)
            if 1 < f < publickey.n:
                p = publickey.n // f
                q = f
                break
        return self.create_private_key_from_pqe(p, q, publickey.e, publickey.n)

    def test(self):
        from RsaCtfTool.lib.keys_wrapper import PublicKey

        key_data = """-----BEGIN PUBLIC KEY-----
MIGWMA0GCSqGSIb3DQEBAQUAA4GEADCBgAJ5C/QyoZTftkv7F7HOOWqxiRTnW3Sa
mWXYEKiCOio1vK3Xh/HMJdJZ5JsOwd27OTvlBw5eLEjsJfjT0PQR/ULJujjvf35q
4EYr3aw1U4JVcy8h2eyb61AhNDc1GL2YXOIkjUbpj+8I0fKpDjPesfa0h5yhTluo
x5AlBQIDAQAB
-----END PUBLIC KEY-----"""
        result = self.attack(PublicKey(key_data), progress=False)
        return result != (None, None)
