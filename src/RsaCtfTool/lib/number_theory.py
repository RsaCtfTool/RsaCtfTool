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
        logger.warning(
            "[!] Using native python functions for math, which is slow. install gmpy2 with: 'python3 -m pip install <module>'."
        )


def list_prod(list_):
    if not list_:
        return 1
    return reduce(lambda x, y: x * y, list_, 1)


def digit_sum(n):
    """Compute sum of digits efficiently without string conversion."""
    if n == 0:
        return 0
    total = 0
    n = abs(n)
    while n:
        total += n % 10
        n //= 10
    return total


def A007814(n):
    return (~n & n - 1).bit_length()


def A135481(n):
    return ~n & n - 1


def A000265(n):
    return n // (A135481(n) + 1)


def mulmod(a, b, m):
    """Russian-peasant modular multiplication, O(log b), no recursion."""
    a %= m
    result = 0
    while b:
        if b & 1:
            result = (result + a) % m
        a = (a << 1) % m
        b >>= 1
    return result


def getpubkeysz(n):
    if (size := n.bit_length()) & 1 != 0:
        size += 1
    return size


def is_pow2(n):
    return n & (n - 1) == 0


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
    mod = m
    a, x, u = a % m, 0, 1
    while a:
        x, u, m, a = u, x - (m // a) * u, a, m % a
    if m != 1:
        # Match gmpy2's contract: no inverse -> ZeroDivisionError, never
        # a silently wrong value.
        raise ZeroDivisionError("invert() no inverse exists")
    # The extended-gcd walk can end on a negative Bezout coefficient;
    # gmpy2.invert always returns the canonical residue in [0, mod).
    return x % mod


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

    if n < 2:
        return False
    if n in (2, 3):
        return True
    if (n & 1 == 0) or n % 3 == 0:
        return False

    r, s = 0, n - 1
    while s & 1 == 0:
        r += 1
        s >>= 1
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
    If Fermat's prime criterion is false by short circuit we don't need to keep testing bases, so we return false for a guaranteed composite.
    Otherwise we keep trying with primes 3 and 5 as base. The sweet spot is primes 2,3,5, it doesn't improve the running time adding more primes to test as base.
    If all the previous tests pass then we try with Rabin-Miller.
    All the tests are probabilistic.
    """
    if n < 2:
        return False
    # The Fermat criterion degenerates for the small primes themselves:
    # pow(b, n-1, n) == 0 when b == n, so 2, 3 and 5 must be accepted
    # before any base-2/3/5 test runs.
    if n in (2, 3, 5):
        return True
    if n & 1 == 0:
        return False
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


def _primes_first(n):
    """First n primes, pure-Python.

    The gmpy binding of `primes()` means "first n primes" while the
    fallback sieve meant "primes below n"; this fallback matches the gmpy
    semantics so dixon/QS/pollard_P_1 factor bases are identical on both
    backends.
    """
    if n <= 0:
        return []
    if n < 6:
        return [2, 3, 5, 7, 11][:n]
    # Rosser's theorem: the n-th prime is below n*(ln n + ln ln n) for n >= 6.
    bound = int(n * (math.log(n) + math.log(math.log(n)))) + 10
    return erathostenes_sieve(bound)[:n]


def _primes_yield_gmpy(n):
    p = i = 1
    while i <= n:
        p = gmpy.next_prime(p)
        yield p
        i += 1


def _fib(n):
    a, b = 0, 1
    i = 0
    while i < n:
        a, b = b, a + b
        i += 1
    return a


def ilogb(x, b):
    """
    greatest integer l such that b**l <= x (exact integer arithmetic).
    """
    log_count = 0
    while x >= b:
        x //= b
        log_count += 1
    return log_count


def _primes_gmpy(n):
    return list(_primes_yield_gmpy(n))


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


def _mod(a, b):
    return a % b


def _mul(a, b):
    return a * b


def _is_divisible(n, p):
    return n % p == 0


def _is_congruent(a, b, m):
    return (a - b) % m == 0


def _powmod(b, e, m):
    # Three-arg pow also handles negative exponents via the modular
    # inverse, matching gmpy2.powmod on both counts.
    return pow(b, e, m)


def _fac(n):
    """
    Factorial
    """
    tmp = 1
    for m in range(n, 1, -1):
        tmp *= m
    return tmp


def _lucas(n):
    a, b = 2, 1
    for _ in range(n):
        a, b = b, a + b
    return a


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
    primes = _primes_first
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
    is_prime = _is_prime
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


def legendre(a, p):
    """Legendre symbol (a/p) for odd prime p.
    Returns 0 if p|a, 1 if a is a quadratic residue mod p, p-1 (≡ -1) if QNR.
    Uses Euler's criterion: a^((p-1)/2) ≡ (a|p) (mod p).
    Not Jacobi — do NOT use this as a compositeness test.
    """
    if a % p == 0:
        return 0
    return powmod(a, (p - 1) >> 1, p)


def cuberoot(n):
    return introot(n, 3)


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


def trivial_factorization_with_n_phi(n, phi):
    return trivial_factorization_with_n_b(n, n - phi + 1)


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

    c1 = neg_pow(c1, a, n) if a < 0 else powmod(c1, a, n)
    c2 = neg_pow(c2, b, n) if b < 0 else powmod(c2, b, n)
    ct = c1 * c2 % n
    if g == 1:
        return ct
    # The Bezout combination yields m^g mod n; only when m^g < n does the
    # integer g-th root recover m. A truncated root of a wrapped value is
    # garbage - reject it with an exact round-trip check.
    root = int(introot(ct, g))
    return root if pow(root, g) == ct else None


def phi(n, factors):
    """Euler totient φ(n).
    Computed from the prime factorisation of n via:
      φ(n) = n ∏_{p|n} (1 − 1/p).
    The `factors` argument must contain every distinct prime divisor of n.
    """
    y = n
    for p in factors:
        if n % p == 0:
            y //= p
            y *= p - 1
            n, _ = remove(n, p)
    if n > 1:
        if is_prime(n):
            y //= n
            y *= n - 1
        else:
            # A composite residual means `factors` missed a divisor;
            # multiplying (n-1)/n as if it were prime returns a silently
            # wrong totient.
            raise ValueError(
                "phi() got an incomplete factorisation: residual %d is composite" % n
            )
    return y


def chinese_remainder(m, a):
    # The classic product formula requires pairwise coprime moduli; with
    # gmpy a non-invertible Ni silently becomes 0 and yields a wrong
    # residue, so reject the input instead.
    for i, mi in enumerate(m):
        for mj in m[i + 1:]:
            if gcd(mi, mj) != 1:
                raise ValueError(
                    "chinese_remainder: moduli must be pairwise coprime"
                )
    S = 0
    N = list_prod(m)
    for mi, ai in zip(m, a):
        Ni = N // mi
        S += Ni * invert(Ni, mi) * ai
    return S % N


def tonelli(n, p):
    """
    Tonelli-Shanks modular squareroot algorithm
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
    while t != 1:
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
    if not frac:
        return (0, 1)

    num, denom = frac[-1], 1

    for value in reversed(frac[:-1]):
        num, denom = value * num + denom, num

    return num, denom


def convergents_from_contfrac(frac, progress=False):
    """Convergents_from_contfrac implementation"""
    if not frac:
        return []

    convergents = [(0, 1)]

    num_prev, num = 0, 1
    denom_prev, denom = 1, 0

    for value in frac[:-1]:
        num_prev, num = num, value * num + num_prev
        denom_prev, denom = denom, value * denom + denom_prev
        convergents.append((num, denom))

    return convergents

def inv_mod_pow_of_2(factor, bit_count):
    """
    Inverse of an odd factor modulo 2**bit_count via Newton iteration
    x <- x * (2 - factor*x); precision doubles each round, so this stays
    faster than a generic extended-gcd invert.
    """
    if not factor & 1:
        raise ValueError("factor must be odd")
    m = 1 << bit_count
    factor %= m
    acc = 1  # exact inverse modulo 2
    t = 1
    while t < bit_count:
        t = min(bit_count, t << 1)
        acc = (acc * (2 - factor * acc)) % (1 << t)
    return acc % m


def mlucas(v, a, n):
    """Multiply along a Lucas sequence modulo n.

    Given v = V_m(P), returns V_{m*a}(P).  The Chebyshev composition law
    V_m(V_a(x)) = V_{m*a}(x) makes this equally readable as advancing the
    index by a or composing parameters, which is what williams_pp1() relies
    on when it iterates v <- mlucas(v, p, n) to reach V_{seed * p^e}.
    MSB-first binary chain keeping (V_{m*t}, V_{m*t+m}) alive; the identity
    V_{r+s} = V_r*V_s - V_{r-s} with r-s = m supplies the cross term.
    """
    v1, v2 = v, (v * v - 2) % n  # t = 1: V_m, V_2m
    for bit in bin(a)[3:]:
        if bit == "0":
            v1, v2 = (v1 * v1 - 2) % n, (v1 * v2 - v) % n
        else:
            v1, v2 = (v1 * v2 - v) % n, (v2 * v2 - 2) % n
    return v1


def is_lucas(n):
    """
    True if n is a Lucas number (A000032).
    """

    u1, u2 = 1, 3
    if n <= 0:
        return False
    if n <= 2:
        # 1 and 2 are both Lucas numbers (L_1 = 1, L_0 = 2); the old
        # sign() path returned the int +/-1, which is truthy even for
        # non-Lucas and negative inputs.
        return True
    else:
        while n > u2:
            old_u1, u1 = u1, u2
            u2 = old_u1 + u2
    return u2 == n


__all__ = [
    "getpubkeysz",
    "gcd",
    "isqrt",
    "introot",
    "invmod",
    "gcdext",
    "is_square",
    "is_cube",
    "next_prime",
    "is_prime",
    "fib",
    "primes",
    "lcm",
    "invert",
    "powmod",
    "ilog2",
    "ilog",
    "ilog10",
    "mod",
    "log",
    "log2",
    "log10",
    "trivial_factorization_with_n_phi",
    "factor_ned",
    "neg_pow",
    "common_modulus_related_message",
    "phi",
    "list_prod",
    "chinese_remainder",
    "ilogb",
    "mul",
    "cuberoot",
    "isqrt_rem",
    "is_divisible",
    "is_congruent",
    "iroot",
    "dlp_bruteforce",
    "fac",
    "rational_to_contfrac",
    "contfrac_to_rational",
    "convergents_from_contfrac",
    "fdivmod",
    "inv_mod_pow_of_2",
    "mlucas",
    "lucas",
    "mulmod",
    "A000265",
    "powmod_base_list",
    "powmod_exp_list",
    "is_pow2",
    "is_lucas",
    "gmpy_version",
]
