#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from functools import reduce
import binascii
import math
import logging

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
    if size % 2 != 0:
        size += 1
    return size


def _gcdext(a, b):
    if a == 0:
        return [b, 0, 1]
    else:
        g, y, x = _gcdext(b % a, a)
        return [g, x - (b // a) * y, y]


def _isqrt(n):
    if n == 0:
        return 0
    x, y = n, (n + 1) // 2
    while y < x:
        x, y = y, (y + n // y) // 2
    return x


def _gcd(a, b):
    while b:
        a, b = b, a % b
    return abs(a)


def _introot(n, r=2):
    if n < 0:
        return None if r % 2 == 0 else -_introot(-n, r)
    if n < 2:
        return n
    if r == 2:
        return _isqrt(n)
    lower, upper = 0, n
    while lower != upper - 1:
        mid = (lower + upper) // 2
        m = mid ** r
        if m == n:
            return mid
        elif m < n:
            lower = mid
        elif m > n:
            upper = mid
    return lower


def _introot_gmpy(n, r=2):
    if n < 0:
        return None if r % 2 == 0 else -_introot_gmpy(-n, r)
    return gmpy.root(n, r)[0]


def _introot_gmpy2(n, r=2):
    if n < 0:
        return None if r % 2 == 0 else -_introot_gmpy2(-n, r)
    return gmpy.iroot(n, r)[0]


def _invmod(a, m):
    a, x, u = a % m, 0, 1
    while a:
        x, u, m, a = u, x - (m // a) * u, a, m % a
    return x


def _is_square(n):
    i = _isqrt(n)
    return (i**2 == n)


def miller_rabin(n, k=40):
    # Taken from https://gist.github.com/Ayrx/5884790
    # Implementation uses the Miller-Rabin Primality Test
    # The optimal number of rounds for this test is 40
    # See http://stackoverflow.com/questions/6325576/how-many-iterations-of-rabin-miller-should-i-use-for-cryptographic-safe-primes
    # for justification

    # If number is even, it's a composite number

    if n == 2:
        return True

    if n % 2 == 0:
        return False

    r, s = 0, n - 1
    while s % 2 == 0:
        r += 1
        s //= 2
    for _ in xrange(k):
        a = random.randrange(2, n - 1)
        x = pow(a, s, n)
        if x == 1 or x == n - 1:
            continue
        for _ in xrange(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def _next_prime(n):
    while True:
        if _is_prime(n):
            return n
        n+=1


def erathostenes_sieve(n):
    """ Returns  a list of primes < n """
    sieve = [True] * n
    for i in range(3, int(n ** 0.5) + 1, 2):
        if sieve[i]:
            sieve[i * i :: 2 * i] = [False] * ((n - i * i - 1) // (2 * i) + 1)
    return [2] + [i for i in range(3, n, 2) if sieve[i]]
_primes = erathostenes_sieve


def _primes_yield(n):
    p = i = 1
    while i <= n:
      p = next_prime(p)


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


def _invert(a,b):
    return pow(a,b-2,b)


def _lcm(x, y):
   return (x*y)//_gcd(x,y)


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

__all__ = [getpubkeysz, gcd, isqrt, introot, invmod, gcdext , is_square, next_prime, is_prime, fib, primes, lcm, invert, powmod]
