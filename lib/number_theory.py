#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from functools import reduce
import math
import logging
import random

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
        logger.warning("[!] Using native python functions for math, which is slow. install gmpy2 with: 'python3 -m pip install <module>'.")

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


def _isqrt_rem(n):
    i2 = _isqrt(n)
    return i2, n - (i2 * i2)


def _isqrt_gmpy(n):
    return int(gmpy.sqrt(n))


def _isqrt_rem_gmpy(n):
    i2 = _isqrt_gmpy(n)
    return i2, n - (i2 * i2)


def _gcd(a, b):
    while b:
        a, b = b, a % b
    return abs(a)


def _remove(n, p):
    r = n
    c = 0
    while r % p == 0:
        r //= p
        c += 1
    return r, c


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


def _iroot(n, p):
    b = introot(n, p)
    return b, b**p == n


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
    h = n & 0xF
    if h > 9:
        return False
    if h != 2 and h != 3 and h != 5 and h != 6 and h != 7 and h != 8:
        t = _isqrt(n)
        return t * t == n
    return False


def miller_rabin(n, k=40):
    """ "
    Taken from https://gist.github.com/Ayrx/5884790
    Implementation uses the Miller-Rabin Primality Test
    The optimal number of rounds for this test is 40
    See http://stackoverflow.com/questions/6325576/how-many-iterations-of-rabin-miller-should-i-use-for-cryptographic-safe-primes
    for justification
    """

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
    if all(
        (
            _fermat_prime_criterion(n),
            _fermat_prime_criterion(n, b=3),
            _fermat_prime_criterion(n, b=5),
        )
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
    """
    Returns  a list of primes < n
    """
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


def ilogb(x, b):
    """
    greatest integer l such that b**l  < = x.
    """
    l = 0
    while x >= b:
        x /= b
        l += 1
    return l


def _mod(a, b):
    return a % b


def _mul(a, b):
    return a * b


def _is_divisible(n, p):
    return n % p == 0


def _is_congruent(a, b, m):
    return (a - b) % m == 0


def _powmod(b, e, m):
    r = 1
    b %= m
    while e > 0:
        if e & 1 == 1:
            r = (r * b) % m
        e >>= 1
        b = (b * b) % m
    return r


def _fac(n):
    """
    Factorial
    """
    tmp = 1
    for m in range(n, 1, -1):
        tmp *= m
    return tmp


from functools import cache
@cache
def _lucas(n):
   if n == 0: return 2
   if n == 1: return 1
   if n > 1: return _lucas(n - 1) + _lucas(n - 2)


if gmpy_version > 0:
    gcd = gmpy.gcd
    gcdext = gmpy.gcdext
    is_square = gmpy.is_square
    next_prime = gmpy.next_prime
    is_prime = gmpy.is_prime
    fib = gmpy.fib
    primes = _primes_gmpy
    lcm = gmpy.lcm
    invert = gmpy.invert
    invmod = gmpy.invert
    remove = gmpy.remove
    fac = gmpy.fac
    if gmpy_version == 2:
        iroot = gmpy.iroot
        ilog = _ilog_gmpy
        ilog2 = _ilog2_gmpy
        ilog10 = _ilog10_gmpy
        log = gmpy.log
        log2 = gmpy.log2
        log10 = gmpy.log10
        mod = gmpy.f_mod
        mul = gmpy.mul
        powmod = gmpy.powmod
        isqrt_rem = gmpy.isqrt_rem
        isqrt = gmpy.isqrt
        introot = _introot_gmpy2
        is_divisible = gmpy.is_divisible
        is_congruent = gmpy.is_congruent
        fdivmod = gmpy.f_divmod
        lucas = gmpy.lucas
    else:
        iroot = gmpy.root
        ilog = _ilog_math
        ilog2 = _ilog2_math
        ilog10 = _ilog10_math
        log = math.log
        log2 = math.log2
        log10 = math.log10
        mul = _mul
        mod = _mod
        powmod = pow
        isqrt_rem = gmpy.sqrtrem
        isqrt = gmpy.isqrt
        introot = _introot_gmpy
        is_divisible = _is_divisible
        is_congruent = _is_congruent
        fdivmod = gmpy.fdivmod
        lucas = _lucas

else:
    remove = _remove
    iroot = _iroot
    gcd = _gcd
    isqrt = _isqrt
    isqrt_rem = _isqrt_rem
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
    powmod = _powmod
    ilog = _ilog_math
    ilog2 = _ilog2_math
    ilog10 = _ilog10_math
    log = math.log
    log2 = math.log2
    log10 = math.log10
    mod = _mod
    mul = _mul
    is_divisible = _is_divisible
    is_congruent = _is_congruent
    fac = _fac
    fdivmod = divmod
    lucas = _lucas


def cuberoot(n):
    return introot(n, 3)


def trivial_factorization_with_n_phi(N, phi):
    m = N - phi + 1
    m2N2 = pow(m, 2) - (N << 2) # same as isqrt((m**2) - (4*n))
    if m2N2 > 0:
        i = isqrt(m2N2)
        roots = int((m - i) >> 1), int((m + i) >> 1)
        if roots[0] * roots[1] == N:
            return roots


def neg_pow(a, b, n):
    """
    Calculates a^{b} mod n when b is negative
    """
    assert b < 0
    assert gcd(a, n) == 1
    res = int(invert(a, n))
    res = powmod(res, b * (-1), n)
    return res


def common_modulus_related_message(e1, e2, n, c1, c2):
    """
    e1 --> Public Key exponent used to encrypt message m and get ciphertext c1
    e2 --> Public Key exponent used to encrypt message m and get ciphertext c2
    n --> Modulus
    The following attack works only when m^{GCD(e1, e2)} < n
    """

    g, a, b = gcdext(e1, e2)

    if g == 1:
        return None

    if a < 0:
        c1 = neg_pow(c1, a, n)
    else:
        c1 = powmod(c1, a, n)
    if b < 0:
        c2 = neg_pow(c2, b, n)
    else:
        c2 = powmod(c2, b, n)
    ct = c1 * c2 % n
    return int(introot(ct, g))


def phi(n, factors):
    """
    Euler totient function
    """
    if is_prime(n):
        return n - 1
    elif is_square(n):
        i2 = isqrt(n)
        return phi(i2, factors) * i2
    else:
        y = n
        for p in factors:
            if n % p == 0:
                y //= p
                y *= p - 1
                n, _ = remove(n, p)
        if n > 1:
            y //= n
            y *= n - 1
        return y


def list_prod(lst):
    return reduce((lambda x, y: x * y), lst)


def chinese_remainder(m, a):
    S = 0
    N = list_prod(m)
    for i in range(0, len(m)):
        Ni = N // m[i]
        inv = invert(Ni, m[i])
        S += Ni * inv * a[i]
    return S % N


def legendre(a, p):
    return powmod(a, (p - 1) >> 1, p)


def tonelli(n, p):
    """
    tonelli-shanks modular squareroot algorithm
    """
    assert legendre(n, p) == 1, "not a square (mod p)"
    q = p - 1
    s = 0
    while q & 1 == 0:
        q >>= 1
        s += 1
    if s == 1:
        return powmod(n, (p + 1) >> 2, p)
    for z in range(2, p):
        if p - 1 == legendre(z, p):
            break
    c = powmod(z, q, p)
    r = powmod(n, (q + 1) >> 1, p)
    t = powmod(n, q, p)
    m = s
    while (t - 1) % p != 0:
        t2 = powmod(t, 2, p)
        for i in range(1, m):
            if (t2 - 1) % p == 0:
                break
            t2 = powmod(t2, 2, p)
        b = powmod(c, 1 << (m - i - 1), p)
        r = (r * b) % p
        c = powmod(b, 2, p)
        t = (t * c) % p
        m = i
    return r


def is_cube(n):
    i = n % 9
    b = False
    if 0 <= i <= 1 or i == 8:
        a, b = iroot(n, 3)
    return b


def dlp_bruteforce(g, h, p):
    """
    Try to solve the discrete logarithm problem:
    x for g^x == h (mod p) with brute force.
    """
    for x in range(1, p):
        if h == powmod(g, x, p):
            return x
            
            
def rational_to_contfrac(x, y):
    """Rational_to_contfrac implementation"""
    a = x // y
    if a * y == x:
        return [a]
    else:
        pquotients = rational_to_contfrac(y, x - a * y)
        pquotients.insert(0, a)
        return pquotients


def contfrac_to_rational(frac):
    """Contfrac_to_rational implementation"""
    if len(frac) == 0:
        return (0, 1)
    elif len(frac) == 1:
        return (frac[0], 1)
    else:
        remainder = frac[1 : len(frac)]
        (num, denom) = contfrac_to_rational(remainder)
        return (frac[0] * num + denom, num)


def convergents_from_contfrac(frac, progress=False):
    """Convergents_from_contfrac implementation"""
    convs = []
    for i in range(0, len(frac)):
        convs.append(contfrac_to_rational(frac[0:i]))
    return convs


def inv_mod_pow_of_2(factor, bit_count):
    """
    its orders of magnitude faster than invert(a, 2^k)
    code borrowed from:  https://algassert.com/post/1709
    """
    rest = factor & -2
    acc = 1
    for i in range(bit_count):
        if acc & (1 << i): acc -= (rest << i)
    mask = (1 << bit_count) - 1
    return acc & mask


def mlucas(v, a, n):
    """Helper function for williams_pp1().  Multiplies along a Lucas sequence modulo n."""
    v1, v2 = v, (v*v - 2) % n
    while a > 0:
        v1, v2 = (
            ((v1*v1 - 2) % n, (v1 * v2 - v) % n)
            if a & 1 == 0
            else ((v1 * v2 - v) % n, (v2*v2 - 2) % n)
        )
        a >>= 1
    return v1


__all__ = [
    getpubkeysz,
    gcd,
    isqrt,
    introot,
    invmod,
    gcdext,
    is_square,
    is_cube,
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
    common_modulus_related_message,
    phi,
    list_prod,
    chinese_remainder,
    ilogb,
    mul,
    cuberoot,
    isqrt_rem,
    is_divisible,
    is_congruent,
    iroot,
    dlp_bruteforce,
    fac,
    rational_to_contfrac,
    contfrac_to_rational,
    convergents_from_contfrac,
    fdivmod,
    inv_mod_pow_of_2,
    mlucas,
    lucas,
]
