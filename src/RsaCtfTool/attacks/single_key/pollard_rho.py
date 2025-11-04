#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from RsaCtfTool.attacks.abstract_attack import AbstractAttack
from RsaCtfTool.lib.algos import pollard_rho


class Attack(AbstractAttack):
    def __init__(self, timeout=60):
        super().__init__(timeout)
        self.speed = AbstractAttack.speed_enum["slow"]

    def attack(self, publickey, cipher=[], progress=True):
        """Run attack with Pollard Rho"""
        # pollard Rho attack
        try:
            p = pollard_rho(publickey.n)
            publickey.p = p
            publickey.q = publickey.n // publickey.p
            return self.create_private_key_from_pqe(publickey.p, publickey.q, publickey.e, publickey.n)
        except TypeError:
            return None, None

        return None, None

    def test(self):
        from RsaCtfTool.lib.keys_wrapper import PublicKey

        key_data = """-----BEGIN PUBLIC KEY-----
MDwwDQYJKoZIhvcNAQEBBQADKwAwKAIhAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAABAgMBAAE=
-----END PUBLIC KEY-----"""
        self.timeout = 180
        result = self.attack(PublicKey(key_data), progress=False)
        return result != (None, None)
