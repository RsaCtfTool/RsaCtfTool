#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from RsaCtfTool.attacks.abstract_attack import AbstractAttack
from RsaCtfTool.lib.number_theory import primes, is_divisible


class Attack(AbstractAttack):
    def __init__(self, timeout=60):
        super().__init__(timeout)
        self.speed = AbstractAttack.speed_enum["fast"]

    def attack(self, publickey, cipher=[], progress=True):
        """Try an attack where q < 100,000, from RsaCtfTool.BKPCTF2016 - sourcekris"""
        for prime in primes(100000):
            if is_divisible(publickey.n, prime):
                publickey.q = prime
                publickey.p = publickey.n // publickey.q
                return self.create_private_key_from_pqe(publickey.p, publickey.q, publickey.e, publickey.n)

        return None, None

    def test(self):
        from RsaCtfTool.lib.keys_wrapper import PublicKey

        key_data = """-----BEGIN PUBLIC KEY-----
MIGhMA0GCSqGSIb3DQEBAQUAA4GPADCBiwKBgwC60gz5ftUELfaWzk3z5aZ4z0+z
aT098S3+n9P9jMiquLlVM+QU4/wMN39O5UgnEYsdMFYaPHQb6nx2iZeJtRdD4HYJ
LfnrBdyX6xUFzp6xK1q54Qq/VvkgpY5+AOzwWXfocoNN2FhM9KyHy33FAVm9lix1
y++2xqw6MadOfY8eTBDVAgMBAAE=
-----END PUBLIC KEY-----"""
        result = self.attack(PublicKey(key_data), progress=False)
        return result != (None, None)
