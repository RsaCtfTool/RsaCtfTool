from __future__ import division

# http://programmingpraxis.com/2010/04/23/m/
# http://programmingpraxis.com/2010/04/27/m/
# Add two points p1 and p2 given point P0 = P1-P2 modulo n
def _ecadd(p1, p2, p0, n):
    x1, z1 = p1
    x2, z2 = p2
    x0, z0 = p0
    t1, t2 = (x1-z1)*(x2+z2), (x1+z1)*(x2-z2)
    return (z0*pow(t1+t2, 2, n) % n, x0*pow(t1-t2, 2, n) % n)

# double point p on A modulo n
def _ecdub(p, A, n):
    x, z = p
    An, Ad = A
    t1, t2 = pow(x+z, 2, n), pow(x-z, 2, n)
    t = t1 - t2
    return (t1*t2*4*Ad % n, (4*Ad*t2 + t*An)*t % n)

# multiply point p by m on curve A modulo n
def _ecmul(m, p, A, n):
    if m == 0:
        return (0, 0)
    elif m == 1:
        return p
    else:
        q = _ecdub(p, A, n)
        if m == 2:
            return q
        b = 1
        while b < m:
            b *= 2
        b //= 4
        r = p
        while b:
            if m & b:
                q, r = _ecdub(q, A, n), _ecadd(q, r, p, n)
            else:
                q, r = _ecadd(r, q, p, n), _ecdub(r, A, n)
            b //= 2
        return r


def ecm(n, B1=10, B2=20):
    """
    TODO: Determine the best defaults for B1 and B2 and the best way to
          increment them and iters "Modern" ECM using Montgomery curves and an
          algorithm analogous to the two-phase variant of Pollard's p-1 method
    TODO: We currently compute the prime lists from the sieve as we need them,
          but this means that we recompute them at every iteration. While it
          would not be particularly efficient memory-wise, we might be able
          to increase time-efficiency by computing the primes we need ahead of
          time (say once at the beginning and then once each time we increase
          the bounds) and saving them in lists, and then iterate the inner
          while loops over those lists.
    """
    from _primefac._arith import ispower, gcd, ilog
    from _primefac._prime import isprime, primegen
    from six.moves import xrange
    from random import randrange
    import six
    if isprime(n):
        return n
    m = ispower(n)
    if m:
        return m
    iters = 1
    while True:
        for _ in xrange(iters):
            seed = randrange(6, n)
            u, v = (seed**2 - 5) % n, 4*seed % n
            p = pow(u, 3, n)
            Q, C = (pow(v-u, 3, n)*(3*u+v) % n, 4*p*v % n), (p, pow(v, 3, n))
            pg = primegen()
            p = six.next(pg)
            while p <= B1:
                Q, p = _ecmul(p**ilog(B1, p), Q, C, n), six.next(pg)
            g = gcd(Q[1], n)
            if 1 < g < n:
                return g
            while p <= B2:
                """
                "There is a simple coding trick that can speed up the second
                stage. Instead of multiplying each prime times Q, we iterate
                over i from B1 + 1 to B2, adding 2Q at each step; when i is
                prime, the current Q can be accumulated into the running
                solution. Again, we defer the calculation of the greatest
                common divisor until the end of the iteration."
                TODO: Implement this trick and compare performance.
                """
                Q = _ecmul(p, Q, C, n)
                g *= Q[1]
                g %= n
                p = six.next(pg)
            g = gcd(g, n)
            if 1 < g < n:
                return g
            # This seed failed.  Try again with a new one.
        # These bounds failed.  Increase and try again.
        B1 *= 3
        B2 *= 3
        iters *= 2

__all__ = [ecm]

