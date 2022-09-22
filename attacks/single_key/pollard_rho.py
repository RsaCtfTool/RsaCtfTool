#!/usr/bin/env python3
# -*- coding: utf-8 -*-


from attacks.abstract_attack import AbstractAttack
from lib.keys_wrapper import PrivateKey
from lib.number_theory import is_prime, gcd, powmod


class Attack(AbstractAttack):
    def __init__(self, timeout=60):
        super().__init__(timeout)
        self.speed = AbstractAttack.speed_enum["slow"]

    def pollard_rho(self, n, seed=2, p=2, c=1):
        f = lambda x: powmod(x, p, n) + c
        x, y, d = seed, seed, 1
        while d == 1:
            x = f(x)
            y = f(f(y))
            d = gcd((x - y), n)
            if n > d > 1:
                return d

    def attack(self, publickey, cipher=[], progress=True):
        """Run attack with Pollard Rho"""
        if not hasattr(publickey, "p"):
            publickey.p = None
        if not hasattr(publickey, "q"):
            publickey.q = None

        # pollard Rho attack
        try:
            try:
                poll_res = self.pollard_rho(publickey.n)
            except RecursionError:
                print("RecursionError")
                return None, None

            if poll_res is not None:
                publickey.p = poll_res
                publickey.q = publickey.n // publickey.p

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
MDwwDQYJKoZIhvcNAQEBBQADKwAwKAIhAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAABAgMBAAE=
-----END PUBLIC KEY-----"""
        self.timeout = 180
        result = self.attack(PublicKey(key_data), progress=False)
        return result != (None, None)
