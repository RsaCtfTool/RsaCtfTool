from __future__ import division

def pollardRho_brent(n):
    from _primefac._arith import gcd
    from _primefac._prime import isprime
    from six.moves import xrange
    from random import randrange
    if isprime(n):
        return n
    g = n
    while g == n:
        y, c, m, g, r, q = randrange(1, n), randrange(1, n), randrange(1, n), 1, 1, 1
        while g == 1:
            x, k = y, 0
            for _ in xrange(r):
                y = (y**2 + c) % n
            while k < r and g == 1:
                ys = y
                for _ in xrange(min(m, r-k)):
                    y = (y**2 + c) % n
                    q = q * abs(x-y) % n
                g, k = gcd(q, n), k+m
            r *= 2
        if g == n:
            while True:
                ys = (ys**2+c) % n
                g = gcd(abs(x-ys), n)
                if g > 1:
                    break
    return g

__all__ = [pollardRho_brent]
