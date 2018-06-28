from __future__ import division


# http://programmingpraxis.com/2010/04/27/modern/
# TODO: What are the best default bounds and way to increment them?
def pollard_pm1(n, B1=100, B2=1000):
    from _primefac._arith import ispower, gcd, ilog
    from _primefac._prime import isprime, primegen
    import six
    if isprime(n):
        return n
    m = ispower(n)
    if m:
        return m
    while True:
        pg = primegen()
        q = 2           # TODO: what about other initial values of q?
        p = six.next(pg)
        while p <= B1:
            q, p = pow(q, p**ilog(B1, p), n), six.next(pg)
        g = gcd(q-1, n)
        if 1 < g < n:
            return g
        while p <= B2:
            q, p = pow(q, p, n), six.next(pg)
        g = gcd(q-1, n)
        if 1 < g < n:
            return g
        # These bounds failed.  Increase and try again.
        B1 *= 10
        B2 *= 10

__all__ = [pollard_pm1]
