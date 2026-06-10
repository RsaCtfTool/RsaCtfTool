#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from RsaCtfTool.attacks.abstract_attack import AbstractAttack
from RsaCtfTool.lib.algos import quadratic_sieve


class Attack(AbstractAttack):
    def __init__(self, timeout=60):
        super().__init__(timeout)
        self.speed = AbstractAttack.speed_enum["slow"]

    def attack(self, publickey, cipher=[], progress=True):
        """Run the Quadratic Sieve factorisation attack"""
        try:
            if not hasattr(publickey, "p"):
                publickey.p = None
            if not hasattr(publickey, "q"):
                publickey.q = None

            poll_res = quadratic_sieve(publickey.n, progress=progress)

            if poll_res is not None:
                publickey.p, publickey.q = poll_res

            return self.create_private_key_from_pqe(
                publickey.p, publickey.q, publickey.e, publickey.n
            )
        except TypeError:
            return None, None

    def test(self):
        from RsaCtfTool.lib.keys_wrapper import PublicKey

        key_data = """-----BEGIN PUBLIC KEY-----
MCAwDQYJKoZIhvcNAQEBBQADDwAwDAIFAQAwAjcCAwEAAQ==
-----END PUBLIC KEY-----"""
        self.timeout = 180
        result = self.attack(PublicKey(key_data), progress=False)
        return result != (None, None)
