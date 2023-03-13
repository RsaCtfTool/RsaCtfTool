#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from attacks.abstract_attack import AbstractAttack
from tqdm import tqdm
from lib.keys_wrapper import PrivateKey
from lib.number_theory import gcd


class Attack(AbstractAttack):
    def __init__(self, timeout=60):
        super().__init__(timeout)
        self.speed = AbstractAttack.speed_enum["medium"]

    def attack(self, publickey, cipher=[], progress=True):
        """Run tests against fermat composites"""
        limit = 30
        p = q = None
        for x in tqdm(range(2, limit), disable=(not progress)):
            f = (1 << (1 << x)) + 1
            g = gcd(f, publickey.n)
            if 1 < g < publickey.n:
                p = publickey.n // g
                q = g
                break
        if p is not None and q is not None:
            priv_key = PrivateKey(int(p), int(q), int(publickey.e), int(publickey.n))
            return priv_key, None
        return None, None

    def test(self):
        from lib.keys_wrapper import PublicKey

        key_data = """-----BEGIN PUBLIC KEY-----
MF4wDQYJKoZIhvcNAQEBBQADTQAwSgJDTuJNJVnOa1qp8n91iIWs30F6xA+I/nkf
MV7Ad/0M5seWOKImUngYig60DRfrXwXa7GWh8qmK0V5sR+ib27+bbZfwAQIDAQAB
-----END PUBLIC KEY-----"""
        result = self.attack(PublicKey(key_data), progress=False)
        return result != (None, None)
