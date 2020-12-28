#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
import logging
from tqdm import tqdm
from sympy import Symbol
from sympy.solvers import solve
from lib.keys_wrapper import PrivateKey
from lib.utils import timeout, TimeoutError


class WienerAttack(object):
    def rational_to_contfrac(self, x, y):
        """Rational_to_contfrac implementation"""
        a = x // y
        if a * y == x:
            return [a]
        else:
            pquotients = self.rational_to_contfrac(y, x - a * y)
            pquotients.insert(0, a)
            return pquotients

    def convergents_from_contfrac(self, frac):
        """Convergents_from_contfrac implementation"""
        convs = []
        for i in tqdm(range(len(frac))):
            convs.append(self.contfrac_to_rational(frac[0:i]))
        return convs

    def contfrac_to_rational(self, frac):
        """Contfrac_to_rational implementation"""
        if len(frac) == 0:
            return (0, 1)
        elif len(frac) == 1:
            return (frac[0], 1)
        else:
            remainder = frac[1 : len(frac)]
            (num, denom) = self.contfrac_to_rational(remainder)
            return (frac[0] * num + denom, num)

    def is_perfect_square(self, n):
        """Is n a perfect square ?"""
        h = n & 0xF
        if h > 9:
            return -1

        if h != 2 and h != 3 and h != 5 and h != 6 and h != 7 and h != 8:
            t = self.isqrt(n)
            if t * t == n:
                return t
            else:
                return -1

        return -1

    def isqrt(self, n):
        """Is n a square ?"""
        if n == 0:
            return 0
        a, b = divmod(n.bit_length(), 2)
        x = 2 ** (a + b)
        while True:
            y = (x + n // x) // 2
            if y >= x:
                return x
            x = y

    def __init__(self, n, e):
        """Constructor"""
        self.d = None
        self.p = None
        self.q = None
        sys.setrecursionlimit(100000)
        frac = self.rational_to_contfrac(e, n)
        convergents = self.convergents_from_contfrac(frac)

        for (k, d) in tqdm(convergents):
            if k != 0 and (e * d - 1) % k == 0:
                phi = (e * d - 1) // k
                s = n - phi + 1
                discr = s * s - 4 * n
                if discr >= 0:
                    t = self.is_perfect_square(discr)
                    if t != -1 and (s + t) % 2 == 0:
                        self.d = d
                        x = Symbol("x")
                        roots = solve(x ** 2 - s * x + n, x)
                        if len(roots) == 2:
                            self.p = roots[0]
                            self.q = roots[1]
                        break


def attack(attack_rsa_obj, publickey, cipher=[]):
    """Wiener's attack"""
    with timeout(attack_rsa_obj.args.timeout):
        try:
            wiener = WienerAttack(publickey.n, publickey.e)
            if wiener.p is not None and wiener.q is not None:
                publickey.p = wiener.p
                publickey.q = wiener.q
                priv_key = PrivateKey(
                    int(publickey.p),
                    int(publickey.q),
                    int(publickey.e),
                    int(publickey.n),
                )
                return (priv_key, None)
        except TimeoutError:
            return (None, None)

    return (None, None)
