#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from functools import reduce, cache
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
        logger.warning(
            "[!] Using native python functions for math, which is slow."
            + " install gmpy2 with: 'python3 -m pip install <module>'."
        )


@cache
def list_prod(list_):
    if (ll := len(list_)) == 0:
        return 1
    return list_prod(list_[: ll - 1]) * list_[-1]


digit_sum = lambda n: sum(int(d) for d in str(n))
A007814 = lambda n: (~n & n - 1).bit_length()
A135481 = lambda n: (~n & n - 1)
A000265 = lambda n: n // (A135481(n) + 1)


@cache
def mulmod(a, b, m):
    if b == 0:
        return 0
    if b == 1:
        return a % m
    if b & 1 == 0:
        return mulmod((a << 1) % m, b >> 1, m)
    else:
        return (a + mulmod(a, b - 1, m)) % m


def getpubkeysz(n):
    if (size := n.bit_length()) & 1 != 0:
        size += 1
    return size


is_pow2 = lambda n: n & (n - 1) == 0


def _gcdext(a, b):
    if a == 0:
        return [b, 0, 1]
    d, r = divmod(b, a)
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
        mid = lower + ((upper - lower) >> 1)
        m = pow(mid, r)
        if m == n:
            return mid
        lower = mid * (m < n) + lower * (m >= n)
        upper = mid * (m > n) + upper * (m <= n)
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
    if (h := n & 0xF) > 9 or h in [2, 3, 5, 6, 7, 8]:
        return False
    t = _isqrt(n)
    return t * t == n


def _powmod_base_list(base_lst, exp, mod):
    return list(powmod(i, exp, mod) for i in base_lst)


def _powmod_exp_list(base, exp_lst, mod):
    return list(powmod(base, i, mod) for i in exp_lst)


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
    if (n & 1 == 0) or (digit_sum(n) % 9 in [0, 3, 6]):
        return False

    r, s = 0, n - 1
    while s & 1 == 0:
        r += 1
        s >>= 1
    i = 0
    for _ in range(0, k):
        a = random.randrange(2, n - 1)
        if (x := pow(a, s, n)) in [1, n - 1]:
            continue
        j = 0
        while j <= r - 1:
            if (x := pow(x, 2, n)) == (n - 1):
                break
            j += 1
        else:
            return False
    return True


def _fermat_prime_criterion(n, b=2):
    """Fermat's prime criterion
    Returns False if n is definitely composite, True if possible prime."""
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


def _fib(n):
    a, b = 0, 1
    i = 0
    while i <= n:
        a, b = b, a + b
        i += 1
    return a


def ilogb(x, b):
    """
    greatest integer l such that b**l  < = x.
    """
    l = 0
    while x >= b:
        x /= b
        l += 1
    return l


_primes_gmpy = lambda n: list(_primes_yield_gmpy(n))
_isqrt_gmpy = lambda n: int(gmpy.sqrt(n))
_invert = lambda a, b: pow(a, b - 2, b)
_lcm = lambda x, y: (x * y) // _gcd(x, y)
_ilog2_gmpy = lambda n: int(gmpy.log2(n))
_ilog_gmpy = lambda n: int(gmpy.log(n))
_ilog2_math = lambda n: int(math.log2(n))
_ilog_math = lambda n: int(math.log(n))
_ilog10_math = lambda n: int(math.log10(n))
_ilog10_gmpy = lambda n: int(gmpy.log10(n))
_mod = lambda a, b: a % b
_mul = lambda a, b: a * b
_is_divisible = lambda n, p: n % p == 0
_is_congruent = lambda a, b, m: (a - b) % m == 0


def _powmod(b, e, m):
    r = 1
    b %= m
    while e > 0:
        r = ((r * b) % m) * (e & 1) + r * ((e + 1) & 1)
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


@cache
def _lucas(n):
    if n == 0:
        return 2
    if n == 1:
        return 1
    return _lucas(n - 1) + _lucas(n - 2)


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
        introot = _introot_gmpy2
        is_divisible = gmpy.is_divisible
        is_congruent = gmpy.is_congruent
        fdivmod = gmpy.f_divmod
        lucas = gmpy.lucas
        powmod_base_list = gmpy.powmod_base_list
        powmod_exp_list = gmpy.powmod_exp_list
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
        introot = _introot_gmpy
        is_divisible = _is_divisible
        is_congruent = _is_congruent
        fdivmod = gmpy.fdivmod
        lucas = _lucas
        powmod_base_list = _powmod_base_list
        powmod_exp_list = _powmod_exp_list

    isqrt = gmpy.isqrt
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
    powmod_base_list = _powmod_base_list
    powmod_exp_list = _powmod_exp_list

legendre = lambda a, p: powmod(a, (p - 1) >> 1, p)
cuberoot = lambda n: introot(n, 3)


def factor_ned_probabilistic(n, e, d):
    """
    800-56B R1 Recommendation for Pair-Wise Key Establishment Schemes Using Integer Factorization Cryptography in Appendix C.
    """
    n1, k = n - 1, d * e - 1
    if k & 1 == 1:
        return
    t, r = 0, k
    while r & 1 == 0:
        r >>= 1
        t += 1
    for _ in range(1, 101):
        g = random.randint(0, n1)
        if (y := pow(g, r, n)) == 1 or y == n1:
            continue
        for _ in range(1, t):
            if (x := pow(y, 2, n)) == 1:
                p = gcd(y - 1, n)
                return p, n // p
            if x == n1:
                continue
            y = x
        if (x := pow(y, 2, n)) == 1:
            p = gcd(x - 1, n)
            return p, n // p


def trivial_factorization_with_n_b(n, b):
    if (b2n4 := (b * b) - (n << 2)) > 0:
        i = isqrt(b2n4)
        p, q = int((b - i) >> 1), int((b + i) >> 1)
        if p * q == n:
            return p, q


def factor_ned_deterministic(n, e, d):
    """
    800-56B R2 Recommendation for Pair-Wise Key Establishment Schemes Using Integer Factorization Cryptography in Appendix C.2.
    """
    k = d * e - 1
    m, r = divmod(k * gcd(n - 1, k), n)
    return trivial_factorization_with_n_b(n, ((n - r) // (m + 1)) + 1)


factor_ned = factor_ned_deterministic


trivial_factorization_with_n_phi = lambda n, phi: trivial_factorization_with_n_b(
    n, n - phi + 1
)


def neg_pow(a, b, n):
    """
    Calculates a^{b} mod n when b is negative
    """
    assert b < 0
    assert gcd(a, n) == 1
    res = int(invert(a, n))
    return powmod(res, b * (-1), n)


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

    c1 = neg_pow(c1, a, n) if a < 0 else powmod(c1, a, n)
    c2 = neg_pow(c2, b, n) if a < 0 else powmod(c2, b, n)
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


def chinese_remainder(m, a):
    S = 0
    N = list_prod(m)
    for i in range(0, len(m)):
        Ni = N // m[i]
        S += Ni * invert(Ni, m[i]) * a[i]
    return S % N


def tonelli(n, p):
    """
    tonelli-shanks modular squareroot algorithm
    """
    assert legendre(n, p) == 1, "not a square (mod p)"
    q = p - 1
    q >>= (s := A007814(q))
    if s == 1:
        return powmod(n, (p + 1) >> 2, p)
    for z in range(2, p):
        if p - 1 == legendre(z, p):
            break
    c, r, t, m = powmod(z, q, p), powmod(n, (q + 1) >> 1, p), powmod(n, q, p), s
    while (t - 1) % p != 0:
        t2 = powmod(t, 2, p)
        for i in range(1, m):
            if (t2 - 1) % p == 0:
                break
            t2 = powmod(t2, 2, p)
        b = powmod(c, 1 << (m - i - 1), p)
        # r = (r * b) % p
        r = mulmod(r, b, p)
        c = powmod(b, 2, p)
        # t = (t * c) % p
        t = mulmod(t, c, p)
        m = i
    return r


def is_cube(n):
    b = False
    if (n % 9) in [0, 1, 8]:
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
        remainder = frac[1:]
        (num, denom) = contfrac_to_rational(remainder)
        return (frac[0] * num + denom, num)


def convergents_from_contfrac(frac, progress=False):
    """Convergents_from_contfrac implementation"""
    return [contfrac_to_rational(frac[:i]) for i in range(0, len(frac))]


def inv_mod_pow_of_2(factor, bit_count):
    """
    its orders of magnitude faster than invert(a, 2^k)
    code borrowed from:  https://algassert.com/post/1709
    """
    rest = factor & -2
    acc = 1
    for i in range(bit_count):
        acc -= (acc & (1 << i)) * (rest << i)
    mask = (1 << bit_count) - 1
    return acc & mask


def mlucas(v, a, n):
    """Helper function for williams_pp1().  Multiplies along a Lucas sequence modulo n."""
    v1, v2 = v, (v * v - 2) % n
    while a > 0:
        v1, v2 = (
            ((v1 * v1 - 2) % n, (v1 * v2 - v) % n)
            if a & 1 == 0
            else ((v1 * v2 - v) % n, (v2 * v2 - 2) % n)
        )
        a >>= 1
    return v1


def is_lucas(n):
    """
    True if n is a Lucas number (A000032).
    """
    sign = lambda n: 1 if n > 0 else -1
    u1,u2 = 1,3
    if n<=2: return sign(n)
    else:
        while(n>u2):
            old_u1,u1=u1,u2
            u2=old_u1+u2
    return u2==n


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
    factor_ned,
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
    mulmod,
    A000265,
    powmod_base_list,
    powmod_exp_list,
    is_pow2,
    # is_lucas,
]
