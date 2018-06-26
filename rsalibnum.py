from functools import reduce
import binascii
import math


_primes = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31]
_primes_mask = []


def invmod(a, n):
    """
    Return 1 / a (mod n).
    @a and @n must be co-primes.
    """
    if n < 2:
        raise ValueError("modulus must be greater than 1")

    x, y, g = xgcd(a, n)

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

    return ppx, ppy, a


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


def primes(until):
    """
    Return list of primes not greater than @until. Rather slow.
    """
    global _primes, _primes_mask

    if until < 2:
        return []

    if until <= _primes[-1]:
        for index, prime in enumerate(_primes):
            if prime > until:
                return _primes[:index]

    i = _primes[-1]
    while i < until + 1:
        i += 2
        sqrt = math.sqrt(i) + 1
        for j in _primes:
            if i % j == 0:
                break
            if j > sqrt:
                _primes.append(i)
                break
    return _primes
