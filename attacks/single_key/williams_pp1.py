#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from attacks.abstract_attack import AbstractAttack
from lib.keys_wrapper import PrivateKey
from lib.algos import williams_pp1


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

            if publickey.q is not None:
                priv_key = PrivateKey(
                    int(publickey.p),
                    int(publickey.q),
                    int(publickey.e),
                    int(publickey.n),
                )
                return priv_key, None
        except TypeError:
            return None, None

        return None, None

    def test(self):
        from lib.keys_wrapper import PublicKey

        key_data = """-----BEGIN PUBLIC KEY-----
MCowDQYJKoZIhvcNAQEBBQADGQAwFgIPPNmaqiPnbwxXooFxLcTXAgMBAAE=
-----END PUBLIC KEY-----"""
        self.timeout = 180
        return None, None
