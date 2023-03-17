#!/usr/bin/env python3
# -*- coding: utf-8 -*-


from attacks.abstract_attack import AbstractAttack
from lib.keys_wrapper import PrivateKey
from lib.number_theory import gcd, ilogb, isqrt, next_prime, mlucas
from itertools import count


def williams_pp1(n):
    p, i2 = 2, isqrt(n)
    for v in count(1):
        while True:
            e = ilogb(i2, p)
            if e == 0: break
            for _ in range(e): v = mlucas(v, p, n)
            g = gcd(v - 2, n)
            if 1 < g < n: return g, n // g
            if g == n: break
            p = next_prime(p)
    return None


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
        result = self.attack(PublicKey(key_data), progress=False)
        return result != (None, None)
