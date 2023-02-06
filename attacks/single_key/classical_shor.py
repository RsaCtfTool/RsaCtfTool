#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from attacks.abstract_attack import AbstractAttack
from lib.keys_wrapper import PrivateKey
from lib.exceptions import FactorizationError
from lib.number_theory import gcd, powmod


def shor(n):
    """
    Shor's algorithm: only the classical part of it, implemented in a very naive and linear way.
    Use the quantum period finding function: f(x) = a^x % N to find r, then a^r == 1 (mod N) and that is what the quantum computer
    gives advantage over classical algorithms.
    Here in this code we use a linear search of r of even numbers.
    Equivalent to solving DLP with bruteforce.
    https://en.wikipedia.org/wiki/Shor%27s_algorithm
    """
    for a in range(2, n):
        if gcd(n, a):
            for r in range(2, n, 2):
                ar = powmod(a, r, n)
                if ar == 1:
                    ar2 = powmod(a, r >> 1, n)
                    if ar2 != -1:
                        g1 = gcd(ar2 - 1, n)
                        g2 = gcd(ar2 + 1, n)
                        if (n > g1 > 1) or (n > g2 > 1):
                            p = max(max(min(n, g1), 1), max(min(n, g2), 1))
                            q = n // p
                            return (p, q)


class Attack(AbstractAttack):
    def __init__(self, timeout=60):
        super().__init__(timeout)
        self.speed = AbstractAttack.speed_enum["medium"]

    def attack(self, publickey, cipher=[], progress=True):
        """Run Shor attack with a timeout"""
        try:
            publickey.p, publickey.q = shor(publickey.n)

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
MCAwDQYJKoZIhvcNAQEBBQADDwAwDAIFCAjGeKUCAwEAAQ==
-----END PUBLIC KEY-----"""
        result = self.attack(PublicKey(key_data), progress=False)
        return result != (None, None)
