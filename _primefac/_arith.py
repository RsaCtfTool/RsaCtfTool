from __future__ import print_function, division
import six

from _primefac import _util, _prime

def _gcd(a, b):
    while b:
        a, b = b, a % b
    return abs(a)


def _isqrt(n):
    if n == 0:
        return 0
    x, y = n, (n + 1) // 2
    while y < x:
        x, y = y, (y + n//y) // 2
    return x


def _introot(n, r=2):
    if n < 0:
        return None if r % 2 == 0 else -introot(-n, r)
    if n < 2:
        return n
    if r == 2:
        return isqrt(n)
    lower, upper = 0, n
    while lower != upper - 1:
        mid = (lower + upper) // 2
        m = mid**r
        if m == n:
            return mid
        elif m < n:
            lower = mid
        elif m > n:
            upper = mid
    return lower


def _introot_gmpy(n, r=2):
    if n < 0:
        return None if r % 2 == 0 else -introot(-n, r)
    return _util.gmpy.root(n, r)[0]


def _introot_gmpy2(n, r=2):
    if n < 0:
        return None if r % 2 == 0 else -introot(-n, r)
    return _util.gmpy.iroot(n, r)[0]


def _jacobi(a, p):
    if (p % 2 == 0) or (p < 0):
        return None  # p must be a positive odd number
    if (a == 0) or (a == 1):
        return a
    a, t = a % p, 1
    while a != 0:
        while not a & 1:
            a //= 2
            if p & 7 in (3, 5):
                t *= -1
        a, p = p, a
        if (a & 3 == 3) and (p & 3) == 3:
            t *= -1
        a %= p
    return t if p == 1 else 0


# greatest integer l such that b**l <= x.
def ilog(x, b):
    l = 0
    while x >= b:
        x //= b
        l += 1
    return l


# Returns the largest integer that, when squared/cubed/etc, yields n, or 0 if no such integer exists.
# Note that the power to which this number is raised will be prime.
def ispower(n):
    for p in _prime.primegen():
        r = introot(n, p)
        if r is None:
            continue
        if r ** p == n:
            return r
        if r == 1:
            return 0


# legendre symbol (a|m)
# TODO: which is faster?
def _legendre1(a, p):
    return ((pow(a, (p-1) >> 1, p) + 1) % p) - 1

def _legendre2(a, p):  # TODO: pretty sure this computes the Jacobi symbol
    if a == 0:
        return 0
    x, y, L = a, p, 1
    while 1:
        if x > (y >> 1):
            x = y - x
            if y & 3 == 3:
                L = -L
        while x & 3 == 0:
            x >>= 2
        if x & 1 == 0:
            x >>= 1
            if y & 7 == 3 or y & 7 == 5:
                L = -L
        if x == 1:
            return ((L+1) % p) - 1
        if x & 3 == 3 and y & 3 == 3:
            L = -L
        x, y = y % x, x


def _legendre_gmpy(n, p):
    if (n > 0) and (p % 2 == 1):
        return _util.gmpy.legendre(n, p)
    else:
        return _legendre1(n, p)

# modular sqrt(n) mod p
# p must be prime
def mod_sqrt(n, p):
    a = n % p
    if p % 4 == 3:
        return pow(a, (p+1) >> 2, p)
    elif p % 8 == 5:
        v = pow(a << 1, (p-5) >> 3, p)
        i = ((a*v*v << 1) % p) - 1
        return (a*v*i) % p
    elif p % 8 == 1:  # Shank's method
        q, e = p-1, 0
        while q & 1 == 0:
            e += 1
            q >>= 1
        n = 2
        while legendre(n, p) != -1:
            n += 1
        w, x, y, r = pow(a, q, p), pow(a, (q+1) >> 1, p), pow(n, q, p), e
        while True:
            if w == 1:
                return x
            v, k = w, 0
            while v != 1 and k+1 < r:
                v = (v*v) % p
                k += 1
            if k == 0:
                return x
            d = pow(y, 1 << (r-k-1), p)
            x, y = (x*d) % p, (d*d) % p
            w, r = (w*y) % p, k
    else:
        return a  # p == 2

# modular inverse of a mod m
def _modinv(a, m):
    a, x, u = a % m, 0, 1
    while a:
        x, u, m, a = u, x - (m//a)*u, a, m % a
    return x

def _modinv_gmpy(a, m):
    return int(_util.gmpy.invert(a, m))


if _util.gmpy_version > 0:
    gcd = _util.gmpy.gcd
    jacobi = _util.gmpy.jacobi
    legendre = _legendre_gmpy
    modinv = _modinv_gmpy
    if _util.gmpy_version == 2:
        isqrt = _util.gmpy.isqrt
        introot = _introot_gmpy2
    else:
        isqrt = _util.gmpy.sqrt
        introot = _introot_gmpy
else:
    gcd = _gcd
    isqrt = _isqrt
    introot = _introot
    jacobi = _jacobi
    legendre = _legendre1
    modinv = _modinv

__all__ = [gcd, isqrt, introot, jacobi, ispower, legendre, modinv, mod_sqrt,
           ilog]
