#!/usr/bin/env python3
# -*- coding: utf-8 -*-


from attacks.abstract_attack import AbstractAttack
from lib.keys_wrapper import PrivateKey
from lib.number_theory import is_prime, gcd, powmod

def pollard_rho(n):
  d, x, y, g = 1, 2, 2, lambda x:powmod(x, 2, n)-1
  while d == 1:
    x, y = g(x), g(g(y))
    d = gcd(abs(y-x), n)
  return d

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
