#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
import time
import math
from random import randint
from tqdm import tqdm
from itertools import count
from RsaCtfTool.lib.exceptions import FactorizationError
from RsaCtfTool.lib.number_theory import (
    isqrt,
    gcd,
    primes,
    powmod,
    is_square,
    next_prime,
    A000265,
    isqrt_rem,
    inv_mod_pow_of_2,
    trivial_factorization_with_n_phi,
    cuberoot,
    mod,
    log,
    ilog10,
    ilog2,
    fib,
    rational_to_contfrac,
    convergents_from_contfrac,
    fdivmod,
    is_congruent,
    is_divisible,
    ilogb,
    mlucas,
    iroot,
)
from RsaCtfTool.lib.number_theory import invmod, introot, find_period, is_prime, legendre, tonelli

sys.setrecursionlimit(100000)


def brent(N):
    """Pollard rho with brent optimizations taken from: https://gist.github.com/ssanin82/18582bf4a1849dfb8afd"""
    if N & 1 == 0:
        return 2
    if is_prime(N):
        return N
    g = N
    while g == N:
        y, c, m = randint(1, N - 1), randint(1, N - 1), randint(1, N - 1)
        g, r, q = 1, 1, 1
        while g == 1:
            x = y
            i = 0
            while i <= r:
                y = (powmod(y, 2, N) + c) % N
                i += 1
            k = 0
            while k < r and g == 1:
                ys = y
                i = 0
                while i <= min(m, r - k):
                    y = (powmod(y, 2, N) + c) % N
                    q = q * (abs(x - y)) % N
                    i += 1
                g, k = gcd(q, N), k + m
                if N > g > 1:
                    return g
            r <<= 1
        if g == N:
            while True:
                ys = (powmod(ys, 2, N) + c) % N
                g = gcd(abs(x - ys), N)
                if N > g > 1:
                    return g


def strong_pseudoprime(N):
    """Find a factor of N using the strong pseudoprime (Miller-Rabin) test.
    Iterates prime bases a, climbs the ladder a^f, a^{2f}, a^{4f}, ..., a^{N-1},
    and returns a factor when a nontrivial square root of 1 is found.
    Ref: Wagstaff, "The Joy of Factoring", §3.7 (strong pseudoprime test),
    and §10.4 (factoring Carmichael numbers).
    """
    f = N1 = N - 1
    e = 0
    while f & 1 == 0:
        f >>= 1
        e += 1
    a = 2
    while a <= N1:
        b = powmod(a, f, N)
        if b == 1 or b == N1:
            a = next_prime(a)
            continue
        for _ in range(e):
            prev = b
            b = (b * b) % N
            if b == 1:
                p = gcd(prev - 1, N)
                q = gcd(prev + 1, N)
                if 1 < p < q:
                    return p, q
                break
        a = next_prime(a)
    return []


def close_factor(n, b, progress=True):
    """
    source: https://web.archive.org/web/20201031000312/https://grocid.net/2017/09/16/finding-close-prime-factorizations/
    """
    # approximate phi
    phi_approx = n - 2 * isqrt(n) + 1
    # Create a look-up table
    # If phi_approx is odd we are going to search for odd i values in the lookup table,
    # else we are going to search for even i values in the lookup table.
    look_up = {}
    z = 1
    parity = phi_approx & 1
    for i in tqdm(range(0, b + 1), disable=(not progress)):
        if i & 1 == parity:
            look_up[z] = i
        z <<= 1
        z -= (z >= n) * n

    # check the table
    mu = invmod(powmod(2, phi_approx, n), n)
    fac = powmod(2, b, n)

    for i in tqdm(range(0, (b * b) + 1), disable=(not progress)):
        if mu in look_up:
            phi = phi_approx + look_up[mu] - (i * b)
            r = trivial_factorization_with_n_phi(n, phi)
            if r is not None:
                return r
        mu = (mu * fac) % n


def prime_base_collision(n):
    """Prime-base square-collision factoring.
    Iterates i from ⌊√n⌋ upward computing i² mod n.  When i² ≡ p² (mod n)
    for the current prime p, returns gcd(i−p, n).  Falls back to the next
    prime if no collision is found in the full range.
    Note: this is NOT Dixon's smooth-number factorisation.
    """
    start, basej2N, base = isqrt(n), [4 % n], [2]
    while True:
        lp = base[-1]
        for i in range(start, n):
            i2N = pow(i, 2, n)
            if i2N == basej2N[-1]:
                p = gcd(i - lp, n)
                if 1 < p < n:
                    return p, n // p
        base.append(next_prime(lp))
        basej2N.append(pow(base[-1], 2, n))


def _collect_dixon_relations(n, base, t, n_needed, progress):
    """Collect B-smooth relations a² ≡ ∏ pⱼ^{eⱼ} (mod n).

    Returns (relations, split) where *split* is (p, q) if an immediate
    factor was found (a² ≡ 0 or a² ≡ 1 with a ≢ ±1), else (list, None).
    """
    relations = []
    with tqdm(total=n_needed, disable=not progress, desc="Dixon relations") as pbar:
        while len(relations) < n_needed:
            a = randint(2, n - 1)
            a2 = powmod(a, 2, n)

            if a2 == 0:
                g = gcd(a, n)
                if 1 < g < n:
                    return relations, (g, n // g)

            if a2 == 1 and a != 1 and a != n - 1:
                g = gcd(a - 1, n)
                if 1 < g < n:
                    return relations, (g, n // g)

            temp = a2
            full_exp = [0] * t
            for idx, p in enumerate(base):
                while temp % p == 0:
                    temp //= p
                    full_exp[idx] += 1
            if temp == 1:
                parity = 0
                for idx in range(t):
                    if full_exp[idx] & 1:
                        parity |= 1 << idx
                relations.append((a, parity, full_exp))
                pbar.update(1)
    return relations, None


def _gaussian_elimination_gf2(rows, t):
    """Gaussian elimination over GF(2) with pivot tracking.

    Each element of *rows* is (bitmask, relation_mask).  Returns the
    transformed list in reduced row-echelon form.
    """
    m = len(rows)
    pivot_row = 0
    for col in range(t):
        found = -1
        for i in range(pivot_row, m):
            if (rows[i][0] >> col) & 1:
                found = i
                break
        if found == -1:
            continue
        rows[pivot_row], rows[found] = rows[found], rows[pivot_row]
        for i in range(m):
            if i != pivot_row and (rows[i][0] >> col) & 1:
                rows[i] = (
                    rows[i][0] ^ rows[pivot_row][0],
                    rows[i][1] ^ rows[pivot_row][1],
                )
        pivot_row += 1
    return rows


def _try_smooth_dependency(rows, relations, base, t, n):
    """Try each null-space vector for a nontrivial split x² ≡ y² (mod n).

    Returns (p, q) on success, None if every dependency gives x ≡ ±y.
    """
    m = len(relations)
    for bits, rel_mask in rows:
        if bits == 0 and rel_mask & (rel_mask - 1):
            x = 1
            total_exp = [0] * t
            for i in range(m):
                if (rel_mask >> i) & 1:
                    x = (x * relations[i][0]) % n
                    for j in range(t):
                        total_exp[j] += relations[i][2][j]
            y = 1
            for j, p in enumerate(base):
                if total_exp[j]:
                    y = (y * pow(p, total_exp[j] // 2, n)) % n
            if x != y and x != n - y:
                g = gcd(x - y, n)
                if 1 < g < n:
                    return g, n // g
    return None


def dixon(n, B=None, progress=True, n_extra=40, max_retries=3):
    """Dixon's smooth-number factorisation (Dixon, Math. Comp. 36, 1981).
    Collects relations a_i² ≡ ∏ pⱼ^{e_{ij}} (mod n) that are B-smooth,
    solves a linear dependency over GF(2) to obtain x² ≡ y² (mod n),
    and returns gcd(x−y, n).

    Heuristic complexity: L[1/2, √2] = exp(√(2 log n log log n)).
    In practice superseded by QS/NFS, but included for pedagogical completeness.
    """
    if n & 1 == 0:
        return 2, n // 2

    if B is None:
        ln = log(n)
        B = max(10, int(math.exp((ln * math.log(ln) / 2) ** 0.5)) + 1)

    base = primes(B)
    t = len(base)
    n_needed = t + n_extra

    for _attempt in range(max_retries):
        relations, split = _collect_dixon_relations(n, base, t, n_needed, progress)
        if split is not None:
            return split
        if len(relations) < t + 5:
            continue

        rows = [(relations[i][1], 1 << i) for i in range(len(relations))]
        rows = _gaussian_elimination_gf2(rows, t)
        split = _try_smooth_dependency(rows, relations, base, t, n)
        if split is not None:
            return split

    return None


def _build_qs_factor_base(n, B):
    """Build QS factor base: -1 + primes (from first B primes).

    Every prime p <= the B-th prime is included. Sieving roots:
      - p = 2              → root x ≡ n mod 2 (odd n → every other x)
      - (n|p) = 1          → Tonelli-Shanks gives two roots
      - (n|p) = 0          → p divides n, root 0 (x ≡ 0 mod p ⇒ p|Q(x))
      - otherwise (QNR)    → Q(x) mod p is never 0 for any x (skip)

    Returns (base, sqrt_map) where base has -1 at index 0.
    """
    base = [-1]
    sqrt_map = {}
    for p in primes(B):
        if p == 2:
            sqrt_map[2] = (n & 1,)  # odd n → Q(x) even when x odd
            base.append(2)
            continue
        ls = legendre(n % p, p)
        if ls == 1:
            r = tonelli(n % p, p)
            sqrt_map[p] = (r, p - r)
            base.append(p)
        elif ls == 0:
            sqrt_map[p] = (0,)
            base.append(p)
    return base, sqrt_map


def _qs_sieve_interval(n, base, sqrt_map, M, progress=True):
    """Sieve Q(x) = x^2 - n over x in [sqrt(n)-M, sqrt(n)+M].

    Returns list of (x, parity_mask, full_exp) relations compatible
    with _try_smooth_dependency / _gaussian_elimination_gf2.
    """
    t = len(base)
    X = isqrt(n)
    relations = []

    with tqdm(total=2 * M + 1, disable=not progress, desc="QS trial") as pbar:
        for off in range(-M, M + 1):
            x = X + off
            q_val = x * x - n
            if q_val == 0:
                pbar.update(1)
                continue

            abs_q = abs(q_val)
            temp = abs_q
            full_exp = [0] * t
            if q_val < 0:
                full_exp[0] = 1

            for p_idx in range(1, t):
                p = base[p_idx]
                while temp % p == 0:
                    temp //= p
                    full_exp[p_idx] += 1

            if temp == 1:
                parity = 0
                for idx in range(t):
                    if full_exp[idx] & 1:
                        parity |= 1 << idx
                relations.append((x, parity, full_exp))
            pbar.update(1)

    return relations


def quadratic_sieve(n, B=None, M=None, progress=True, n_extra=10, max_retries=6):
    """Quadratic Sieve factorisation.

    Complexity: L[1/2, 1] = exp(sqrt(log n log log n)).

    Sieves Q(x) = x^2 - n for B-smooth values, then reuses the same
    GF(2) linear algebra and dependency-checking as Dixon.
    """
    if n & 1 == 0:
        return 2, n // 2

    if B is None:
        ln_n = log(n)
        ln_ln_n = math.log(ln_n)
        B_opt = int(math.exp(0.5 * (ln_n * ln_ln_n) ** 0.5))
        if B_opt > 10:
            B = max(10, int(B_opt / math.log(B_opt)))
        else:
            B = max(10, B_opt)

    if M is None:
        M = max(B * 300, 200000)

    base, sqrt_map = _build_qs_factor_base(n, B)
    t = len(base)
    if t < 2:
        return None

    n_needed = t + n_extra
    for _attempt in range(max_retries):
        relations = _qs_sieve_interval(n, base, sqrt_map, M, progress)

        if len(relations) < n_needed:
            M = min(M * 2, 5000000)
            continue

        rows = [(relations[i][1], 1 << i) for i in range(len(relations))]
        rows = _gaussian_elimination_gf2(rows, t)
        split = _try_smooth_dependency(rows, relations, base, t, n)
        if split is not None:
            return split
        M = min(M * 2, 5000000)

    return None


def euler(n):
    """Euler's factorisation method.
    Finds two distinct representations of n as a sum of two squares,
    then recovers factors via GCD of the mixed sums/differences.
    Returns None if fewer than two representations are found.
    """
    end, a, b, solutionsFound, firstb, lf = isqrt(n), 0, 0, [], -1, 0

    while a < end:
        b, f = isqrt_rem(n - a**2)
        if f == 0 and (a != firstb) and (b != firstb):
            solutionsFound.append([b, a])
            firstb = b
            lf = len(solutionsFound)
            if lf == 2:
                break
        a += 1

    if lf < 2:
        return None

    a = solutionsFound[0][0]
    b = solutionsFound[0][1]
    c = solutionsFound[1][0]
    d = solutionsFound[1][1]

    k = gcd(a - c, d - b) ** 2
    h = gcd(a + c, d + b) ** 2
    m_val = gcd(a + c, d - b) ** 2
    lev = gcd(a - c, d + b) ** 2

    return gcd(k + h, n), gcd(lev + m_val, n)


def factor_2PN(N, P=3):
    """
    based on: https://github.com/hirogwa/crypto-playground/blob/master/break_rsa.py
    premise: P is prime > 2 and sqrt(2PN) is close to (Pp + 2q)/2
    M = (Pp + 2q)/2 is a midpoint of (Pp, 2q).
    Note that since both p and q are odd, A = M + 0.5 is an integer.
    There exits an integer x such that
    min(Pp, 2q) = A - x - 1
    max(Pp, 2q) = A + x
    It follows;
    N = pq = (A-x-1)(A+x)/2P = (A^2 - x^2 - A - x)/2P
    => 2PN = A^2 - x^2 - A - x
    => x^2 + x + (-A^2 + A + 2PN) = 0
    We can obtain p,q from A and N via quadratic formula.
    """

    P2N = (P * N) << 1
    A, remainder = isqrt_rem(P2N)
    A += int(remainder != 0)

    c = -(A * A) + A + P2N
    disc = 1 - (c << 2)

    if disc >= 0:
        isqrtdisc = isqrt(disc)

        for x in [(-1 + isqrtdisc) >> 1, (-1 - isqrtdisc) >> 1]:
            if x < 0:
                continue

            # 2q < Pp
            p = (A + x) // P
            q = (A - x - 1) >> 1
            if p * q == N:
                return p, q

            # Pp < 2q
            p = (A - x - 1) // P
            q = (A + x) >> 1
            if p * q == N:
                return p, q

    return []


def factor_XYXZ(n, base=3):
    """Factor n of the form x^y · x^z = x^{y+z} where x is prime.
    Uses integer root extraction: for each exponent k ≥ 2, compute
    the k-th root r = floor(n^{1/k}); if r^k = n and r is prime, return (r, r^{k-1}).
    """
    max_power = int(log(n) / log(base))
    for k in range(2, max_power + 1):
        r, exact = iroot(n, k)
        if exact and is_prime(r):
            return r, n // r


def fermat(n):
    if (n - 2) & 3 == 0:  # Congruence n = 2 (mod 4).
        raise FactorizationError
    a, rem = isqrt_rem(n)
    b2 = -rem
    c0 = (a << 1) + 1
    c = c0
    while not is_square(b2):
        b2 += c
        c += 2
    a = (c - 1) >> 1
    b = isqrt(b2)
    return a - b, a + b


def InverseInverseSqrt2exp(n, k):
    """
    Computes an approximation to the modular inverse square root of `n` with `k` bits.
    """
    a = 1
    t = 3
    while t < k:
        t = min(k, (t << 1) - 2)
        # Update `a` using a Newton-Raphson-like iteration for inverse square roots.
        a = (a * (3 - (a * a) * n) >> 1) & ((1 << t) - 1)
    return inv_mod_pow_of_2(a, k)


def FactorHighAndLowBitsEqual(n, max_middle_bits=24):
    """
    Code taken and heavy modified from https://github.com/google/paranoid_crypto/blob/main/paranoid_crypto/lib/rsa_util.py
    Licensed under open source Apache License Version 2.0, January 2004.
    """
    if ((n_size := n.bit_length()) < 6) or (n & 7 != 1):
        return None
    k = (n_size + 1) >> 1
    r0 = InverseInverseSqrt2exp(n, k + 1)
    if r0 is None:
        raise ArithmeticError("expecting that square root exists")
    a = isqrt(n - 1) + 1
    k_shift = 1 << k

    for middle_bits in range(1, max_middle_bits + 1):
        print(f"middle bits: {middle_bits} of {n_size}/2")
        for r in [r0, k_shift - r0]:
            s = a
            for i in range(k):
                if ((s ^ r) >> i) & 1:
                    m = min(middle_bits, i)
                    shift_val = 1 << (i - m)  # Pre-compute shift value
                    for _ in range(1 << m):
                        s += shift_val
                        d = (s * s) - n
                        if is_square(d):
                            d_sqrt = isqrt(d)
                            return (s - d_sqrt, s + d_sqrt)


class Fibonacci:
    def __init__(self, progress=False, verbose=False):
        self.progress = progress
        self.verbose = verbose

    def _fib_res(self, n, p):
        """fibonacci sequence nth item modulo p"""
        if n == 0:
            return (0, 1)
        a, b = self._fib_res(n >> 1, p)
        c = mod((mod(a, p) * mod(((b << 1) - a), p)), p)
        d = mod((powmod(a, 2, p) + powmod(b, 2, p)), p)
        return (c, d) if n & 1 == 0 else (d, mod((c + d), p))

    def get_n_mod_d(self, n, d, use="mersenne"):
        if n < 0:
            ValueError("Negative arguments not implemented")
        if use == "gmpy":
            return mod(fib(n), d)
        elif use == "mersenne":
            return powmod(2, n, d) - 1
        else:
            return self._fib_res(n, d)[0]

    def get_period_bigint(self, N, min_accept, xdiff):
        search_len = int(pow(N, (1.0 / 6) / 100))

        search_len = max(search_len, min_accept)
        if self.verbose:
            print("Search_len: %d, log2(N): %d" % (search_len, ilog2(N)))

        starttime = time.time()
        p_len = 10 ** (((ilog10(N) + xdiff) >> 1) + 1)
        begin, end = N - p_len, N + p_len
        begin = max(begin, 1)
        if self.verbose:
            print("Search begin: %d, end: %d" % (begin, end))

        look_up = {
            self.get_n_mod_d(x, N): x
            for x in tqdm(range(search_len), disable=(not self.progress))
        }

        if self.verbose:
            print("Searching...")

        while True:
            randi = randint(begin, end)
            if (res := self.get_n_mod_d(randi, N)) > 0 and res in look_up:
                if randi > (res_n := look_up[res]):
                    if (phi_guess := randi - res_n) & 1 == 0 and self.get_n_mod_d(
                        phi_guess, N
                    ) == 0:
                        td = int(time.time() - starttime)
                        if self.verbose:
                            # print(
                            #     "For N = %d Found T:%d, randi: %d, time used %f secs."
                            #     % (N, T, randi, td)
                            # )
                            print(
                                "For N = %d Found randi: %d, time used %f secs."
                                % (N, randi, td)
                            )
                        return phi_guess
                    else:
                        if self.verbose:
                            # print(
                            #     "For N = %d\n Found res: %d, res_n: %d , T: %d\n but failed!"
                            #     % (N, res, res_n, T)
                            # )
                            print(
                                "For N = %d\n Found res: %d, res_n: %d\n but failed!"
                                % (
                                    N,
                                    res,
                                    res_n,
                                )
                            )

    def factorization(self, N, min_accept, xdiff):
        phi_guess = self.get_period_bigint(N, min_accept, xdiff)
        if phi_guess is not None:
            return trivial_factorization_with_n_phi(N, phi_guess)


def hart(N):
    """
    Hart's one line attack
    taken from wagstaff the joy of factoring
    """
    m = 2
    i = 1
    while not is_square(m):
        s = isqrt(N * i) + 1
        m = pow(s, 2, N)
        i += 1
    t = isqrt(m)
    g = gcd(s - t, N)
    return g, N // g


def kraitchik(n):
    x = isqrt(n)
    while True:
        x2 = x * x
        y2 = x2 - n
        while y2 >= 0:
            if is_square(y2):
                y = isqrt(y2)
                z, w = x + y, x - y
                if z % n != 0 and w % n != 0:
                    return gcd(z, n), gcd(w, n)
            y2 -= n
        x += 1


def lehman(n):
    """
    based on: https://programmingpraxis.com/2017/08/22/lehmans-factoring-algorithm/
    """
    if is_congruent(n, 2, 4):
        raise FactorizationError

    for k in range(1, cuberoot(n)):
        nk4 = n * k << 2
        ki4 = isqrt(k) << 2
        ink4 = isqrt(nk4) + 1
        i6 = introot(n, 6)
        ink4i6ki4 = ink4 + (i6 // (ki4)) + 1
        for a in range(ink4, ink4i6ki4):
            b2 = (a * a) - nk4
            if is_square(b2):
                b = isqrt(b2)
                p = gcd(a + b, n)
                q = gcd(a - b, n)
                return p, q
    return []


def lehmer_machine(n):
    """
    fermat based integer factorization
    """
    if (n - 2) & 3 == 0:  # Congruence n = 2 (mod 4).
        raise FactorizationError
    y = 1
    while not is_square(n + y**2):
        y += 1
    x = isqrt(n + y**2)
    return x - y, x + y


def solve_partial_q(n, e, dp, dq, qi, part_q, progress=True, Limit=100000):
    """Search for partial q.
    Tunable to search longer.

    Source:
    https://0day.work/0ctf-2016-quals-writeups/

    Based on:
    RSA? Challenge in 0ctf 2016

    we are given a private key masked and have the components of the
    chinese remainder theorem and a partial "q"

    The above writeup detailed a method to derive q candidates
    given the CRT component dQ

    CRT Components definition
    dP    = e^-1 mod(p-1)
    dQ    = e^-1 mod(q-1)
    qInv  = q^-1 mod p

    Equations from https://0day.work/0ctf-2016-quals-writeups/

    dP Equalities
    -------------
    dP                 = d mod (p - 1)
    dP                 = d mod (p - 1)
    e * dP             = 1 mod (p - 1)
    e * dP - k*(p - 1) = 1
    e * dP             = 1 + k*(p-1)
    e * dP -1          = k*(p-1)
    (e * dP -1)/k      = (p-1)
    (e * dP -1)/k +1   = p

    dQ Equalities
    -------------
    dQ                 = d mod (q - 1)
    dQ                 = d mod (q - 1)
    e * dQ             = 1 mod (q - 1)
    e * dQ - k*(p - 1) = 1
    e * dQ             = 1 + k*(q-1)
    e * dQ -1          = k*(q-1)
    (e * dQ -1)/k      = (q-1)
    (e * dQ -1)/k +1   = p

    qInv Equalities
    ---------------
    qInv            = q^-1 mod p
    q * qInv        = 1 (mod p)
    q * qInv - k*p  = 1            (For some value "k")
    q * qInv        = 1 + k*p
    q * qInv - 1    = k*p
    (q * qInv -1)/k = p

    Additionally the following paper details an algorithm to generate
    p and q prime candidates with just the CRT components

    https://eprint.iacr.org/2004/147.pdf
    """

    edqm1 = e * dq - 1
    edpm1 = e * dp - 1

    found_q = False
    for j in tqdm(range(Limit, 1, -1), disable=(not progress)):
        q = edqm1 // j + 1
        if q & part_q == part_q:
            found_q = True
            break

    if not found_q:
        raise FactorizationError("partial q not found")

    if n > q and n % q == 0:
        return q, n // q

    found_p = False
    for k in tqdm(range(1, Limit, 1), disable=(not progress)):
        p = edpm1 // k + 1
        if gcd(p, q) == 1 and invmod(q, p) == qi:
            found_p = True
            break

    if not found_p or p * q != n:
        raise FactorizationError("partial p not found")

    return p, q


def pollard_P_1(n, progress=True):
    """Pollard P1 implementation"""
    z = []
    logn = log(isqrt(n))
    prime = primes(997)

    for j in range(0, len(prime)):
        primej = prime[j]
        logp = log(primej)
        z.extend(primej for _ in range(1, int(logn / logp) + 1))

    for pp in tqdm(prime, disable=(not progress)):
        for i in range(0, len(z)):
            pp = powmod(pp, z[i], n)
            p = gcd(n, pp - 1)
            if n > p > 1:
                return p, n // p


def pollard_rho(n):
    d, x, y, g = 1, 2, 2, lambda x: powmod(x, 2, n) - 1
    while d == 1:
        x, y = g(x), g(g(y))
        d = gcd(abs(y - x), n)
    return d


def shor(n):
    """
    Shor's algorithm: only the classical part of it, implemented in a very naive and linear way.
    Use the quantum period finding function: f(x) = a^x % N to find r, then a^r == 1 (mod N) and that is what the quantum computer
    gives advantage over classical algorithms.
    Here in this code we use a linear search of r of even numbers.
    Equivalent to solving DLP with bruteforce.
    https://en.wikipedia.org/wiki/Shor%27s_algorithm
    """
    for a in range(2, n):
        # a should be coprime of n otherwise it is a trivial factor of n.
        if (g := gcd(n, a)) != 1:
            return g, n // g
        for r in range(
            2, n, 2
        ):  # from this step is that it shoul be run in a quantum computer, but we are doing a linear search.
            if powmod(a, r, n) == 1:
                if (ar2 := powmod(a, r >> 1, n)) != -1:
                    g1, g2 = gcd(ar2 - 1, n), gcd(ar2 + 1, n)
                    if (n > g1 > 1) or (n > g2 > 1):
                        p = max(max(min(n, g1), 1), max(min(n, g2), 1))
                        return (p, n // p)


def SQUFOF(N):
    """
    Code borrowed and adapted from the wikipedia: https://en.wikipedia.org/wiki/Shanks%27s_square_forms_factorization
    It may contain bugs
    """

    multiplier = [
        1,
        3,
        5,
        7,
        11,
        3 * 5,
        3 * 7,
        3 * 11,
        5 * 7,
        5 * 11,
        7 * 11,
        3 * 5 * 7,
        3 * 5 * 11,
        3 * 7 * 11,
        5 * 7 * 11,
        3 * 5 * 7 * 11,
    ]

    if (N - 2) & 3 == 0:  # Congruence n = 2 (mod 4).
        raise FactorizationError

    s = isqrt(N)
    L = isqrt(s << 1) << 1
    B = 3 * L

    for k in range(0, len(multiplier)):
        D = multiplier[k] * N
        Po = Pprev = P = isqrt(D)
        Qprev = 1
        Q = D - (Po * Po)
        for i in range(2, B + 1):
            b = (Po + P) // Q
            P = b * Q - P
            q = Q
            Q = Qprev + b * (Pprev - P)
            r = isqrt(Q)
            if not (i & 1) and (r * r) == Q:
                break
            Pprev, Qprev = P, q
        b = (Po - P) // r
        Pprev = P = b * r + P
        Qprev = r
        Q = (D - (Pprev * Pprev)) // Qprev
        c1 = True
        while c1:
            b = (Po + P) // Q
            Pprev = P
            P = b * Q - P
            q = Q
            Q = Qprev + b * (Pprev - P)
            Qprev = q
            c1 = P != Pprev
        r = gcd(N, Qprev)
        if 1 < r < N:
            return r, N // r
    return None


def pollard_strassen(n):
    """
    https://math.stackexchange.com/questions/185524/pollard-strassen-algorithm
    """
    f, c = [], iroot(n, 4)[0]
    for i in range(0, c):
        f.append(1)
        jmin = i * c + 1
        jmax = jmin + c - 1
        for j in range(jmin, jmax + 1):
            f[i] = (f[i] * j) % n
            if (g := gcd(f[i], n)) > 1:
                return g, n // g


def wiener(n, e, progress=True):
    convergents = convergents_from_contfrac(rational_to_contfrac(e, n))

    for k, d in tqdm(convergents, disable=(not progress)):
        if k != 0:
            phi, q = fdivmod((e * d) - 1, k)
            if (phi & 1 == 0) and (q == 0):
                s = n - phi + 1
                discr = (s * s) - (n << 2)  # same as  s**2 - 4*n
                t = 0
                if discr > 0 and is_square(discr):
                    t = isqrt(discr)
                if (s + t) & 1 == 0:
                    pq = trivial_factorization_with_n_phi(n, phi)
                    if pq is not None:
                        return pq


def williams_pp1(n):
    p, i2 = 2, isqrt(n)
    for v in count(1):
        while True:
            e = ilogb(i2, p)
            if e == 0:
                break
            for _ in range(e):
                v = mlucas(v, p, n)
            g = gcd(v - 2, n)
            if 1 < g < n:
                return g, n // g
            if g == n:
                break
            p = next_prime(p)
    return None


def difference_of_powers_factor(n):
    """
    Idea based on: https://github.com/trizen/perl-scripts/blob/master/Math/difference_of_powers_factorization_method.pl
    """
    F = set()
    for a in range(2, isqrt(n) + 1):
        a_k = a
        for k in range(1, int(log(n) / log(a)) + 1):
            if (1 << k) > n:
                break
            a_k *= a
            if a_k > n:
                break
            for sign in [-1, 1]:
                if (b_k := a_k + sign * n) > 0:
                    b, e = iroot(b_k, k)
                    if e and b > 1:
                        if 1 < (f1 := gcd(a - b, n)) < n:
                            F.add(f1)
                        if 1 < (f2 := gcd(a + b, n)) < n:
                            F.add(f2)
    return sorted(F)


def repunit_factor(n):
    z = find_period(n)
    if z == -1:
        return None
    num_bits = n.bit_length()
    k = num_bits // z
    R = (1 << (k * z)) - 1
    R //= (1 << z) - 1
    p = gcd(n, R)
    return p, n // p
