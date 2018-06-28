from __future__ import division

def mlucas(v, a, n):
    """
    Helper function for williams_pp1().
      Multiplies along a Lucas sequence modulo n.
    """
    v1, v2 = v, (v**2 - 2) % n
    for bit in bin(a)[3:]:
        v1, v2 = ((v1**2 - 2) % n, (v1*v2 - v) % n) if bit == "0" else ((v1*v2 - v) % n, (v2**2 - 2) % n)
    return v1

def williams_pp1(n):
    from _primefac._arith import ispower, ilog, isqrt, gcd
    from _primefac._prime import isprime, primegen
    from six.moves import xrange
    import itertools
    if isprime(n):
        return n
    m = ispower(n)
    if m:
        return m
    for v in itertools.count(1):
        for p in primegen():
            e = ilog(isqrt(n), p)
            if e == 0:
                break
            for _ in xrange(e):
                v = mlucas(v, p, n)
            g = gcd(v - 2, n)
            if 1 < g < n:
                return g
            if g == n:
                break

__all__ = [williams_pp1, mlucas]
