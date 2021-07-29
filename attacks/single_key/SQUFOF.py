#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from attacks.abstract_attack import AbstractAttack
from lib.keys_wrapper import PrivateKey
from lib.exceptions import FactorizationError
from lib.utils import timeout, TimeoutError
from lib.rsalibnum import gcd, isqrt


# Code borrowed and adapted from the wikipedia: https://en.wikipedia.org/wiki/Shanks%27s_square_forms_factorization
# It may contain bugs
multiplier = [
    1,
    3,
    5,
    7,
    11,
    3 * 5,
    3 * 7,
    3 * 11,
    5 * 7,
    5 * 11,
    7 * 11,
    3 * 5 * 7,
    3 * 5 * 11,
    3 * 7 * 11,
    5 * 7 * 11,
    3 * 5 * 7 * 11,
]


def SQUFOF(N):
    s = int(isqrt(N) + 0.5)
    L = int(2 * isqrt(2 * s))

    if s ** 2 == N:
        return s
    for k in range(0, len(multiplier)):
        D = multiplier[k] * N
        Po = Pprev = P = isqrt(D)
        Qprev = 1
        Q = D - pow(Po, 2)
        B = 3 * L
        c0 = True
        i = 2
        while c0:
            b = int((Po + P) // Q)
            P = b * Q - P
            q = Q
            Q = Qprev + b * (Pprev - P)
            r = int(isqrt(Q) + 0.5)
            if not (i & 1) and (pow(r, 2) == Q):
                break
            Qprev = q
            Pprev = P
            i += 1
            c0 = i <= B
        b = (Po - P) // r
        Pprev = P = b * r + P
        Qprev = r
        Q = (D - pow(Pprev, 2)) // Qprev
        i = 0
        c1 = True
        while c1:
            b = int((Po + P) // Q)
            Pprev = P
            P = b * Q - P
            q = Q
            Q = Qprev + b * (Pprev - P)
            Qprev = q
            i += 1
            c1 = P != Pprev
        r = gcd(N, Qprev)
        if 1 < r < N:
            return r, N // r
    return -1


class Attack(AbstractAttack):
    def __init__(self, timeout=60):
        super().__init__(timeout)
        self.speed = AbstractAttack.speed_enum["medium"]

    def attack(self, publickey, cipher=[], progress=True):
        """Run fermat attack with a timeout"""
        try:
            with timeout(seconds=self.timeout):
                try:
                    publickey.p, publickey.q = SQUFOF(publickey.n)
                except TimeoutError:
                    return (None, None)

        except FactorizationError:
            return (None, None)

        if publickey.p is not None and publickey.q is not None:
            try:
                priv_key = PrivateKey(
                    n=publickey.n,
                    p=int(publickey.p),
                    q=int(publickey.q),
                    e=int(publickey.e),
                )
                return (priv_key, None)
            except ValueError:
                return (None, None)

        return (None, None)

    def test(self):
        from lib.keys_wrapper import PublicKey

        key_data = """-----BEGIN PUBLIC KEY-----
MCYwDQYJKoZIhvcNAQEBBQADFQAwEgILBX8QDBSnBgSxZ+0CAwEAAQ==
-----END PUBLIC KEY-----"""
        result = self.attack(PublicKey(key_data), progress=False)
        return result != (None, None)
