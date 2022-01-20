#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from functools import reduce
import binascii
import math
import logging
import random
from Crypto.Util.number import bytes_to_long

logger = logging.getLogger("global_logger")

try:
    import gmpy2 as gmpy

    gmpy_version = 2
    mpz = gmpy.mpz
    logger.info("[+] Using gmpy version 2 for math.")
except ImportError:
    try:
        import gmpy

        gmpy_version = 1
        mpz = gmpy.mpz
        logger.info("[+] Using gmpy version 1 for math.")
    except ImportError:
        gmpy_version = 0
        mpz = int
        gmpy = None
        logger.info("[+] Using python native functions for math.")


def getpubkeysz(n):
    size = int(math.log2(n))
    if size & 1 != 0:
        size += 1
    return size


def _gcdext(a, b):
    if a == 0:
        return [b, 0, 1]
    else:
        d = b // a
        r = b - (d * a)
        g, y, x = _gcdext(r, a)
        return [g, x - d * y, y]


def _isqrt(n):
    if n == 0:
        return 0
    x, y = n, (n + 1) >> 1
    while y < x:
        x, y = y, (y + n // y) >> 1
    return x


def _gcd(a, b):
    while b:
        a, b = b, a % b
    return abs(a)


def _introot(n, r=2):
    if n < 0:
        return None if r & 1 == 0 else -_introot(-n, r)
    if n < 2:
        return n
    if r == 2:
        return _isqrt(n)
    lower, upper = 0, n
    while lower != upper - 1:
        mid = (lower + upper) >> 1
        m = pow(mid, r)
        if m == n:
            return mid
        elif m < n:
            lower = mid
        elif m > n:
            upper = mid
    return lower


def _introot_gmpy(n, r=2):
    if n < 0:
        return None if r & 1 == 0 else -_introot_gmpy(-n, r)
    return gmpy.root(n, r)[0]


def _introot_gmpy2(n, r=2):
    if n < 0:
        return None if r & 1 == 0 else -_introot_gmpy2(-n, r)
    return gmpy.iroot(n, r)[0]


def _invmod(a, m):
    a, x, u = a % m, 0, 1
    while a:
        x, u, m, a = u, x - (m // a) * u, a, m % a
    return x


def _is_square(n):
    i = _isqrt(n)
    return i ** 2 == n


def miller_rabin(n, k=40):
    # Taken from https://gist.github.com/Ayrx/5884790
    # Implementation uses the Miller-Rabin Primality Test
    # The optimal number of rounds for this test is 40
    # See http://stackoverflow.com/questions/6325576/how-many-iterations-of-rabin-miller-should-i-use-for-cryptographic-safe-primes
    # for justification

    # If number is even, it's a composite number

    if n == 2:
        return True

    if n & 1 == 0:
        return False

    r, s = 0, n - 1
    while s & 1 == 0:
        r += 1
        s >>= 1
    i = 0
    for i in range(0, k):
        a = random.randrange(2, n - 1)
        x = pow(a, s, n)
        if x == 1 or x == n - 1:
            continue
        j = 0
        while j <= r - 1:
            x = pow(x, 2, n)
            if x == n - 1:
                break
            j += 1
        else:
            return False
    return True


def _fermat_prime_criterion(n, b=2):
    """Fermat's prime criterion
    Returns False if n is definitely composite, True if posible prime."""
    return pow(b, n - 1, n) == 1


def _is_prime(n):
    """
    If fermats prime criterion is false by short circuit we dont need to keep testing bases, so we return false for a guaranteed composite.
    Otherwise we keep trying with primes 3 and 5 as base. The sweet spot is primes 2,3,5, it doesn't improvee the runing time adding more primes to test as base.
    If all the previus tests pass then we try with rabin miller.
    All the tests are probabilistic.
    """
    if (
        _fermat_prime_criterion(n)
        and _fermat_prime_criterion(n, b=3)
        and _fermat_prime_criterion(n, b=5)
    ):
        return miller_rabin(n)
    else:
        return False


def _next_prime(n):
    while True:
        if _is_prime(n):
            return n
        n += 1


def erathostenes_sieve(n):
    """ Returns  a list of primes < n """
    sieve = [True] * n
    for i in range(3, isqrt(n) + 1, 2):
        if sieve[i]:
            sieve[pow(i, 2) :: (i << 1)] = [False] * (
                (n - pow(i, 2) - 1) // (i << 1) + 1
            )
    return [2] + [i for i in range(3, n, 2) if sieve[i]]


_primes = erathostenes_sieve


def _primes_yield(n):
    p = i = 1
    while i <= n:
        p = next_prime(p)
        yield p
        i += 1


def _primes_yield_gmpy(n):
    p = i = 1
    while i <= n:
        p = gmpy.next_prime(p)
        yield p
        i += 1


def _primes_gmpy(n):
    return list(_primes_yield_gmpy(n))


def _fib(n):
    a, b = 0, 1
    i = 0
    while i <= n:
        a, b = b, a + b
        i += 1
    return a


def _invert(a, b):
    return pow(a, b - 2, b)


def _lcm(x, y):
    return (x * y) // _gcd(x, y)


def _ilog2_gmpy(n):
    return int(gmpy.log2(n))


def _ilog_gmpy(n):
    return int(gmpy.log(n))


def _ilog2_math(n):
    return int(math.log2(n))


def _ilog_math(n):
    return int(math.log(n))


def _ilog10_math(n):
    return int(math.log10(n))


def _ilog10_gmpy(n):
    return int(gmpy.log10(n))


def _mod(a, b):
    return a % b


if gmpy_version > 0:
    gcd = gmpy.gcd
    invmod = gmpy.invert
    gcdext = gmpy.gcdext
    is_square = gmpy.is_square
    next_prime = gmpy.next_prime
    is_prime = gmpy.is_prime
    fib = gmpy.fib
    primes = _primes_gmpy
    lcm = gmpy.lcm
    invert = gmpy.invert
    powmod = gmpy.powmod
    ilog = _ilog_gmpy
    ilog2 = _ilog2_gmpy
    mod = gmpy.f_mod
    log = gmpy.log
    log2 = gmpy.log2
    log10 = gmpy.log10
    ilog10 = _ilog10_gmpy
    if gmpy_version == 2:
        isqrt = gmpy.isqrt
        introot = _introot_gmpy2
    else:
        isqrt = gmpy.sqrt
        introot = _introot_gmpy
else:
    gcd = _gcd
    isqrt = _isqrt
    introot = _introot
    invmod = _invmod
    gcdext = _gcdext
    is_square = _is_square
    next_prime = _next_prime
    fib = _fib
    primes = erathostenes_sieve
    is_prime = _is_prime
    fib = _fib
    primes = _primes
    lcm = _lcm
    invert = _invmod
    powmod = pow
    ilog = _ilog_math
    ilog2 = _ilog2_math
    mod = _mod
    log = math.log
    log2 = math.log2
    log10 = math.log10
    ilog10 = _ilog10_math


def trivial_factorization_with_n_phi(N, phi):
    m = N - phi + 1
    i = isqrt(pow(m, 2) - (N << 2))  # same as isqrt((m**2) - (4*n))
    roots = int((m - i) >> 1), int((m + i) >> 1)
    if roots[0] * roots[1] == N:
        return roots


# Calculates a^{b} mod n when b is negative
def neg_pow(a, b, n):
    assert b < 0
    assert gcd(a, n) == 1
    res = int(invert(a, n))
    res = powmod(res, b * (-1), n)
    return res


# e1 --> Public Key exponent used to encrypt message m and get ciphertext c1
# e2 --> Public Key exponent used to encrypt message m and get ciphertext c2
# n --> Modulus
# The following attack works only when m^{GCD(e1, e2)} < n
def common_modulus(e1, e2, n, c1, c2):
    c1 = bytes_to_long(c1)
    c2 = bytes_to_long(c2)
    g, a, b = gcdext(e1, e2)
    if a < 0:
        c1 = neg_pow(c1, a, n)
    else:
        c1 = powmod(c1, a, n)
    if b < 0:
        c2 = neg_pow(c2, b, n)
    else:
        c2 = powmod(c2, b, n)
    ct = c1 * c2 % n
    m = int(introot(ct, g)[0])
    return m


__all__ = [
    getpubkeysz,
    gcd,
    isqrt,
    introot,
    invmod,
    gcdext,
    is_square,
    next_prime,
    is_prime,
    fib,
    primes,
    lcm,
    invert,
    powmod,
    ilog2,
    ilog,
    ilog10,
    mod,
    log,
    log2,
    log10,
    trivial_factorization_with_n_phi,
    neg_pow,
    common_modulus,
]
