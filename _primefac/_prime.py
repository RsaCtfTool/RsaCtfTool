from __future__ import print_function, division
from six.moves import xrange

import six
import itertools

from _primefac import _util

# Recursive sieve of Eratosthenes
def primegen():
    yield 2
    yield 3
    yield 5
    yield 7
    yield 11
    yield 13
    ps = primegen()  # yay recursion
    p = six.next(ps) and six.next(ps)
    q, sieve, n = p**2, {}, 13
    while True:
        if n not in sieve:
            if n < q:
                yield n
            else:
                next_, step = q + 2*p, 2*p
                while next_ in sieve:
                    next_ += step
                sieve[next_] = step
                p = six.next(ps)
                q = p**2
        else:
            step = sieve.pop(n)
            next_ = n + step
            while next_ in sieve:
                next_ += step
            sieve[next_] = step
        n += 2

def primes(n):
    # The primes STRICTLY LESS than n
    return list(itertools.takewhile(lambda p: p < n, primegen()))

def nextprime(n):
    if n < 2:
        return 2
    if n == 2:
        return 3
    n = (n + 1) | 1    # first odd larger than n
    m = n % 6
    if m == 3:
        if isprime(n+2):
            return n+2
        n += 4
    elif m == 5:
        if isprime(n):
            return n
        n += 2
    for m in itertools.count(n, 6):
        if isprime(m):
            return m
        if isprime(m+4):
            return m+4

def pfactor(n):
    s, d, q = 0, n-1, 2
    while not d & q - 1:
        s, q = s+1, q*2
    return s, d // (q // 2)

def _sprp(n, a, s=None, d=None):
    if n % 2 == 0:
        return False
    if (s is None) or (d is None):
        s, d = pfactor(n)
    x = pow(a, d, n)
    if x == 1:
        return True
    for _ in xrange(s):
        if x == n - 1:
            return True
        x = pow(x, 2, n)
    return False


def _sprp_gmpy2(n, a, s=None, d=None):
    return _util.gmpy.is_strong_prp(n, a)

# Used in SLPRP.  TODO: figure out what this does.
def chain(n, u1, v1, u2, v2, d, q, m):
    k = q
    while m > 0:
        u2, v2, q = (u2*v2) % n, (v2*v2 - 2*q) % n, (q*q) % n
        if m % 2 == 1:
            u1, v1 = u2*v1+u1*v2, v2*v1+u2*u1*d
            if u1 % 2 == 1:
                u1 = u1 + n
            if v1 % 2 == 1:
                v1 = v1 + n
            u1, v1, k = (u1//2) % n, (v1//2) % n, (q*k) % n
        m //= 2
    return u1, v1, k

def _isprime(n, tb=(3, 5, 7, 11), eb=(2,), mrb=()):  # TODO: more streamlining
    from _primefac import _arith
    # tb: trial division basis
    # eb: Euler's test basis
    # mrb: Miller-Rabin basis

    # This test suite's first false positve is unknown but has been shown to
    # be greater than 2**64.
    # Infinitely many are thought to exist.

    if n % 2 == 0 or n < 13 or n == _arith.isqrt(n)**2:
        # Remove evens, squares, and numbers less than 13
        return n in (2, 3, 5, 7, 11)
    if any(n % p == 0 for p in tb):
        return n in tb  # Trial division

    for b in eb:  # Euler's test
        if b >= n:
            continue
        if not pow(b, n-1, n) == 1:
            return False
        r = n - 1
        while r % 2 == 0:
            r //= 2
        c = pow(b, r, n)
        if c == 1:
            continue
        while c != 1 and c != n-1:
            c = pow(c, 2, n)
        if c == 1:
            return False

    s, d = pfactor(n)
    if not sprp(n, 2, s, d):
        return False
    if n < 2047:
        return True
    # BPSW has two phases: SPRP with base 2 and SLPRP.
    # We just did the SPRP; now we do the SLPRP:
    if n >= 3825123056546413051:
        d = 5
        while True:
            if _arith.gcd(d, n) > 1:
                p, q = 0, 0
                break
            if _arith.jacobi(d, n) == -1:
                p, q = 1, (1 - d) // 4
                break
            d = -d - 2*d//abs(d)
        if p == 0:
            return n == d
        s, t = pfactor(n + 2)
        u, v, u2, v2, m = 1, p, 1, p, t//2
        k = q
        while m > 0:
            u2, v2, q = (u2*v2) % n, (v2*v2-2*q) % n, (q*q) % n
            if m % 2 == 1:
                u, v = u2*v+u*v2, v2*v+u2*u*d
                if u % 2 == 1:
                    u += n
                if v % 2 == 1:
                    v += n
                u, v, k = (u//2) % n, (v//2) % n, (q*k) % n
            m //= 2
        if (u == 0) or (v == 0):
            return True
        for _ in xrange(1, s):
            v, k = (v*v-2*k) % n, (k*k) % n
            if v == 0:
                return True
        return False

    if not mrb:
        if n < 1373653:
            mrb = [3]
        elif n < 25326001:
            mrb = [3, 5]
        elif n < 3215031751:
            mrb = [3, 5, 7]
        elif n < 2152302898747:
            mrb = [3, 5, 7, 11]
        elif n < 3474749660383:
            mrb = [3, 5, 6, 11, 13]
        elif n < 341550071728321:
            # This number is also a false positive for primes(19+1).
            mrb = [3, 5, 7, 11, 13, 17]
        elif n < 3825123056546413051:
            # Also a false positive for primes(31+1).
            mrb = [3, 5, 7, 11, 13, 17, 19, 23]
    # Miller-Rabin
    return all(sprp(n, b, s, d) for b in mrb)

if _util.gmpy_version == 2:
    sprp = _sprp_gmpy2
    isprime = _util.gmpy.is_bpsw_prp
else:
    sprp = _sprp
    isprime = _isprime

__all__ = [isprime, sprp, chain, pfactor, primegen, primes, nextprime]
