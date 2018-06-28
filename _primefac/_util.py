from __future__ import print_function, division
from six.moves import reduce

try:
    import gmpy2 as gmpy
    gmpy_version = 2
    mpz = gmpy.mpz
except ImportError:
    try:
        import gmpy
        gmpy_version = 1
        mpz = gmpy.mpz
    except ImportError:
        gmpy_version = 0
        mpz = int
        gmpy = None

def listprod(a):
    return reduce(lambda x, y: x * y, a, 1)

__all__ = [listprod, gmpy, gmpy_version, mpz]
