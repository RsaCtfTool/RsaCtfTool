#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from attacks.abstract_attack import AbstractAttack
from lib.keys_wrapper import PrivateKey
from lib.number_theory import gcd, isqrt, is_congruent


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
    if is_congruent(N, 2, 4):
        raise FactorizationError

    s = isqrt(N)
    L = isqrt(s << 1) << 1
    B = 3 * L

    for k in range(0, len(multiplier)):
        D = multiplier[k] * N
        Po = Pprev = P = isqrt(D)
        Qprev = 1
        Q = D - (Po * Po)
        for i in range(2, B + 1):
            b = (Po + P) // Q
            P = b * Q - P
            q = Q
            Q = Qprev + b * (Pprev - P)
            r = isqrt(Q)
            if not (i & 1) and (r * r) == Q: break
            Pprev, Qprev = P, q
        b = (Po - P) // r
        Pprev = P = b * r + P
        Qprev = r
        Q = (D - (Pprev * Pprev)) // Qprev
        c1 = True
        while c1:
            b = (Po + P) // Q
            Pprev = P
            P = b * Q - P
            q = Q
            Q = Qprev + b * (Pprev - P)
            Qprev = q
            c1 = (P != Pprev)
        r = gcd(N, Qprev)
        if 1 < r < N:
            return r, N // r
    return None


class Attack(AbstractAttack):
    def __init__(self, timeout=60):
        super().__init__(timeout)
        self.speed = AbstractAttack.speed_enum["medium"]

    def attack(self, publickey, cipher=[], progress=True):
        """Run fermat attack with a timeout"""

        try:
            publickey.p, publickey.q = SQUFOF(publickey.n)
            if publickey.p is not None and publickey.q is not None:
                priv_key = PrivateKey(
                     n=publickey.n,
                     p=int(publickey.p),
                     q=int(publickey.q),
                     e=int(publickey.e),
                )
                return priv_key, None
            else:
                return None, None
        except:
            return None, None

    def test(self):
        from lib.keys_wrapper import PublicKey

        key_data = """-----BEGIN PUBLIC KEY-----
MCYwDQYJKoZIhvcNAQEBBQADFQAwEgILBX8QDBSnBgSxZ+0CAwEAAQ==
-----END PUBLIC KEY-----"""
        result = self.attack(PublicKey(key_data), progress=False)
        return result != (None, None)
