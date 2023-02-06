#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from attacks.abstract_attack import AbstractAttack
from lib.keys_wrapper import PrivateKey
from lib.number_theory import isqrt, isqrt_rem


def factor_2PN(N, P=3):
    """
    based on: https://github.com/hirogwa/crypto-playground/blob/master/break_rsa.py
    premise: P is prime > 2 and sqrt(2PN) is close to (Pp + 2q)/2
    M = (Pp + 2q)/2 is a midpoint of (Pp, 2q).
    Note that since both p and q are odd, A = M + 0.5 is an integer.
    There exits an integer x such that
    min(Pp, 2q) = A - x - 1
    max(Pp, 2q) = A + x
    It follows;
    N = pq = (A-x-1)(A+x)/2P = (A^2 - x^2 - A - x)/2P
    => 2PN = A^2 - x^2 - A - x
    => x^2 + x + (-A^2 + A + 2PN) = 0
    We can obtain p,q from A and N via quadratic formula.
    """

    P2N = 2 * P * N
    A, remainder = isqrt_rem(P2N)
    if remainder != 0:
        A += 1

    c = -(A**2) + A + P2N
    disc = 1 - (c << 2)

    if disc >= 0:
        isqrtdisc = isqrt(disc)

        for x in [(-1 + isqrtdisc) >> 1, (-1 - isqrtdisc) >> 1]:
            if x < 0:
                continue

            # 2q < Pp
            p = (A + x) // P
            q = (A - x - 1) >> 1
            if p * q == N:
                return p, q

            # Pp < 2q
            p = (A - x - 1) // P
            q = (A + x) >> 1
            if p * q == N:
                return p, q

    return []


class Attack(AbstractAttack):
    def __init__(self, timeout=60):
        super().__init__(timeout)
        self.speed = AbstractAttack.speed_enum["medium"]

    def attack(self, publickey, cipher=[], progress=True):
        """Run factor (2P)N form attack with a timeout"""
        try:
            for z in [3, 5, 7, 11, 13, 17]:
                pq = factor_2PN(publickey.n, z)
                if pq != []:
                    publickey.p, publickey.q = pq
                    break

        except:
            self.logger.error("Internal factorization error...")
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
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQQBZxdhmWmnALU8TFXFgAAAAAAA
AAAAAAAAAAAAAAAAADYUNH0k0DAi1K2rOxXAAAAAAAAAAAAAAAAAAAAAAApBMx+c
xBXy+AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAuBWMwhWfi0AAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAIAGQIDAQAB
-----END PUBLIC KEY-----"""
        result = self.attack(PublicKey(key_data), progress=False)
        return result != (None, None)
