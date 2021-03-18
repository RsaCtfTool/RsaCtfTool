#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from functools import reduce
import binascii


_primes = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31]
_primes_mask = []


def invmod(a, n):
    """
    Return 1 / a (mod n).
    @a and @n must be co-primes.
    """
    if n < 2:
        raise ValueError("modulus must be greater than 1")

    x, g = xgcd(a, n)

    if g != 1:
        raise ValueError("no invmod for given @a and @n")
    else:
        return x % n


def xgcd(a, b):
    """
    Extended Euclid GCD algorithm.
    Return (x, y, g) : a * x + b * y = gcd(a, b) = g.
    """
    if a == 0:
        return 0, 1, b
    if b == 0:
        return 1, 0, a

    px, ppx = 0, 1
    py, ppy = 1, 0

    while b:
        q = a // b
        a, b = b, a % b
        x = ppx - q * px
        y = ppy - q * py
        ppx, px = px, x
        ppy, py = py, y

    return ppx, a


def egcd(a, b):
    if a == 0:
        return [b, 0, 1]
    else:
        g, y, x = egcd(b % a, a)
        return [g, x - (b // a) * y, y]


def modInv(a, m):
    g, x, y = egcd(a, m)
    return x % m


def gcd(*lst):
    """
    Return gcd of a variable number of arguments.
    """
    return abs(reduce(lambda a, b: _gcd(a, b), lst))


def _gcd(a, b):
    """
    Return greatest common divisor using Euclid's Algorithm.
    """
    if a == 0:
        return b
    if b == 0:
        return a
    while b:
        a, b = b, a % b
    return abs(a)


def s2n(s):
    """
    String to number.
    """
    if not len(s):
        return 0
    return int(binascii.hexlify(s), 16)


def n2s(n):
    """
    Number to string.
    """
    s = hex(n)[2:].rstrip("L")
    if len(s) % 2 != 0:
        s = "0" + s

    return binascii.unhexlify(s)
