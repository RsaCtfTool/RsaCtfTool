#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from attacks.abstract_attack import AbstractAttack
from lib.keys_wrapper import PrivateKey
from lib.exceptions import FactorizationError
from lib.number_theory import next_prime, powmod, gcd


def carmichael(N):
    """
    Algorithm described in the Wagstaf's joy of factoring book.
    """
    f = N1 = N - 1
    while f & 1 == 0:
        f >>= 1
    a = 2
    while a <= N1:
        r1 = powmod(a, f << 1, N)
        if r1 == 1:
            r = powmod(a, f, N)
            p = gcd(r - 1, N)
            q = gcd(r + 1, N)
            if q > p > 1:  # and (p * q == N):
                return p, q
        a = next_prime(a)
    return []


class Attack(AbstractAttack):
    def __init__(self, timeout=60):
        super().__init__(timeout)
        self.speed = AbstractAttack.speed_enum["medium"]

    def attack(self, publickey, cipher=[], progress=True):
        """Run carmichael attack with a timeout"""
        try:
            r = carmichael(publickey.n)
            publickey.p, publickey.q = r

        except FactorizationError:
            self.logger.error("N should not be a 4k+2 number...")
            return None, None

        if publickey.p is not None and publickey.q is not None:
            try:
                priv_key = PrivateKey(
                    n=publickey.n,
                    p=int(publickey.p),
                    q=int(publickey.q),
                    e=int(publickey.e),
                )
                return priv_key, None
            except ValueError:
                return None, None

        return None, None

    def test(self):
        from lib.keys_wrapper import PublicKey

        key_data = """-----BEGIN PUBLIC KEY-----
MB8wDQYJKoZIhvcNAQEBBQADDgAwCwIEALpqqQIDAQAB
-----END PUBLIC KEY-----"""
        result = self.attack(PublicKey(key_data), progress=False)
        return result != (None, None)
