#!/usr/bin/env python3
# -*- coding: utf-8 -*-


from attacks.abstract_attack import AbstractAttack
from lib.keys_wrapper import PrivateKey
from lib.utils import timeout, TimeoutError
from lib.rsalibnum import gcd, powmod
from random import randint


def brent(N):
    """ Pollard rho with brent optimizations taken from: https://gist.github.com/ssanin82/18582bf4a1849dfb8afd"""
    if N & 1 == 0:
        return 2
    g = N
    while g == N:
        y, c, m = randint(1, N - 1), randint(1, N - 1), randint(1, N - 1)
        g, r, q = 1, 1, 1
        while g == 1:
            x = y
            i = 0
            while i <= r:
                y = (powmod(y, 2, N) + c) % N
                i += 1
            k = 0
            while k < r and g == 1:
                ys = y
                i = 0
                while i <= min(m, r - k):
                    y = (powmod(y, 2, N) + c) % N
                    q = q * (abs(x - y)) % N
                    i += 1
                g, k = gcd(q, N), k + m
                if N > g > 1:
                    return g
            r <<= 1
        if g == N:
            while True:
                ys = (powmod(ys, 2, N) + c) % N
                g = gcd(abs(x - ys), N)
                if N > g > 1:
                    return g


class Attack(AbstractAttack):
    def __init__(self, timeout=60):
        super().__init__(timeout)
        self.speed = AbstractAttack.speed_enum["slow"]

    def attack(self, publickey, cipher=[], progress=True):
        """Run attack with Pollard Rho-brent"""
        if not hasattr(publickey, "p"):
            publickey.p = None
        if not hasattr(publickey, "q"):
            publickey.q = None

        # pollard Rho-brent attack

        with timeout(self.timeout):
            try:
                try:
                    poll_res = brent(publickey.n)
                except RecursionError:
                    print("RecursionError")
                    return (None, None)

                if poll_res != None:
                    publickey.p = poll_res
                    publickey.q = publickey.n // publickey.p
                    print(publickey.p, publickey.q)

                if publickey.q is not None:
                    priv_key = PrivateKey(
                        int(publickey.p),
                        int(publickey.q),
                        int(publickey.e),
                        int(publickey.n),
                    )
                    return (priv_key, None)
            except TimeoutError:
                return (None, None)
            except TypeError:
                return (None, None)

        return (None, None)

    def test(self):
        from lib.keys_wrapper import PublicKey

        key_data = """-----BEGIN PUBLIC KEY-----
MDwwDQYJKoZIhvcNAQEBBQADKwAwKAIhAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAABAgMBAAE=
-----END PUBLIC KEY-----"""
        self.timeout = 180
        result = self.attack(PublicKey(key_data), progress=False)
        return result != (None, None)
