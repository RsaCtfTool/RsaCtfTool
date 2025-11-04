#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from tqdm import tqdm
from RsaCtfTool.attacks.abstract_attack import AbstractAttack
from RsaCtfTool.lib.number_theory import gcd, ilog2


class Attack(AbstractAttack):
    def __init__(self, timeout=60):
        super().__init__(timeout)
        self.speed = AbstractAttack.speed_enum["medium"]

    def attack(self, publickey, cipher=[], progress=True):
        """Run tests against mersenne composites"""
        p = q = None
        for i in tqdm(range(2, ilog2(publickey.n)), disable=(not progress)):
            i2 = 1 << i
            mersenne = [i2 - 1, i2 + 1]
            g0, g1 = gcd(mersenne[0], publickey.n), gcd(mersenne[1], publickey.n)
            if 1 < g0 < publickey.n:
                p = publickey.n // g0
                q = g0
                break
            if 1 < g1 < publickey.n:
                p = publickey.n // g1
                q = g1
                break
        return self.create_private_key_from_pqe(p, q, publickey.e, publickey.n)

    def test(self):
        from RsaCtfTool.lib.keys_wrapper import PublicKey

        key_data = """-----BEGIN PUBLIC KEY-----
MGIwDQYJKoZIhvcNAQEBBQADUQAwTgJHFe/Y6RPz9BY+fYsJo9d+YAsqKLtte/tI
VyjReeB0fShmpmw8VE1pImeChPevslr2tuc7D/yu5VxYHO/GdP1xUE3nPGYaMkcC
AwEAAQ==
-----END PUBLIC KEY-----"""
        result = self.attack(PublicKey(key_data), progress=False)
        return result != (None, None)
