#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from attacks.abstract_attack import AbstractAttack
from lib.keys_wrapper import PrivateKey
from lib.number_theory import isqrt, is_square, invert, inv_mod_pow_of_2


def InverseInverseSqrt2exp(n, k):
    """
    it does not contemplate k<3
    """
    a = 1
    t = 3
    while t < k:
        t = min(k, (t << 1) - 2)
        a = (a * (3 - (a * a) * n) >> 1) & ((1 << t) - 1)
    return inv_mod_pow_of_2(a, k)


def FactorHighAndLowBitsEqual(n, middle_bits=3):
    """
    Code taken and heavy modified from https://github.com/google/paranoid_crypto/blob/main/paranoid_crypto/lib/rsa_util.py
    Licensed under open source Apache License Version 2.0, January 2004.
    """
    if (n.bit_length() < 6) or (n % 8 != 1):
        return None
    k = (n.bit_length() + 1) >> 1
    r0 = InverseInverseSqrt2exp(n, k + 1)
    if r0 is None:
        raise ArithmeticError("expecting that square root exists")
    a = isqrt(n - 1) + 1
    for r in [r0, (1 << k) - r0]:
        s = a
        for i in range(k):
            if ((s ^ r) >> i) & 1:
                m = min(middle_bits, i)
                for _ in range(1 << m):
                    s += 1 << (i - m)
                    d = (s * s) - n
                    if is_square(d):
                        d_sqrt = isqrt(d)
                        return (s - d_sqrt, s + d_sqrt)
    return None


class Attack(AbstractAttack):
    def __init__(self, timeout=60):
        super().__init__(timeout)
        self.speed = AbstractAttack.speed_enum["medium"]

    def attack(self, publickey, cipher=[], progress=True):
        """Run FactorHighAndLowBitsEqual attack with a timeout"""

        try:
            pq = FactorHighAndLowBitsEqual(publickey.n)
        except:
            pq = None

        if pq is not None:
            publickey.p = pq[0]
            publickey.q = pq[1]

            priv_key = PrivateKey(
                n=publickey.n,
                p=int(publickey.p),
                q=int(publickey.q),
                e=int(publickey.e),
            )
            return priv_key, None

        return None, None

    def test(self):
        from lib.keys_wrapper import PublicKey

        key_data = """-----BEGIN PUBLIC KEY-----
MDwwDQYJKoZIhvcNAQEBBQADKwAwKAIhAKGAooBwksZWSiOH7YSe+0guURdBfMxcOdTR3r4EsjjRAgMBAAE=
-----END PUBLIC KEY-----"""
        result = self.attack(PublicKey(key_data), progress=False)
        return result != (None, None)
