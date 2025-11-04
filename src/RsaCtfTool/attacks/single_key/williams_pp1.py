#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from RsaCtfTool.attacks.abstract_attack import AbstractAttack
from RsaCtfTool.lib.algos import williams_pp1


class Attack(AbstractAttack):
    def __init__(self, timeout=60):
        super().__init__(timeout)
        self.speed = AbstractAttack.speed_enum["slow"]

    def attack(self, publickey, cipher=[], progress=True):
        """Run attack with Pollard Rho-brent"""

        try:
            if not hasattr(publickey, "p"):
                publickey.p = None
            if not hasattr(publickey, "q"):
                publickey.q = None

            # williams p+1 attack

            wres = williams_pp1(publickey.n)

            if wres is not None:
                publickey.p = wres
                publickey.q = publickey.n // publickey.p
                print(publickey.p, publickey.q)

            return self.create_private_key_from_pqe(publickey.p, publickey.q, publickey.e, publickey.n)
        except TypeError:
            return None, None

    def test(self):
        from RsaCtfTool.lib.keys_wrapper import PublicKey

        key_data = """-----BEGIN PUBLIC KEY-----
MCowDQYJKoZIhvcNAQEBBQADGQAwFgIPPNmaqiPnbwxXooFxLcTXAgMBAAE=
-----END PUBLIC KEY-----"""
        self.timeout = 180
        return None, None
