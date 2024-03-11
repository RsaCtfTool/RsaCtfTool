#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
import time
import bitarray
from random import randint
from itertools import count
from lib.exceptions import FactorizationError
from lib.number_theory import isqrt, gcd, primes, powmod, is_square, powmod_base_list, next_prime, A000265, isqrt_rem, inv_mod_pow_of_2, trivial_factorization_with_n_phi, cuberoot, mod, log, ilog10, ilog2, fib, rational_to_contfrac, convergents_from_contfrac, fdivmod, is_congruent, is_divisible, ilogb, mlucas  # , is_prime, invert, contfrac_to_rational
from tqdm import tqdm
from lib.number_theory import invmod, introot

sys.setrecursionlimit(100000)


def brent(N):
    """Pollard rho with brent optimizations taken from: https://gist.github.com/ssanin82/18582bf4a1849dfb8afd"""
    if N & 1 == 0:
        return 2
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


def carmichael(N):
    """
    Algorithm described in the Wagstaf's joy of factoring book.
    """
    f = N1 = N - 1
    # while f & 1 == 0:
    #    f >>= 1
    f = A000265(f)
    a = 2
    while a <= N1:
        if (r1 := powmod(a, f << 1, N)) == 1:
            r = powmod(a, f, N)
            p = gcd(r - 1, N)
            q = gcd(r + 1, N)
            if q > p > 1:  # and (p * q == N):
                return p, q
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


def dixon(N, B=7):
    base = primes(B)
    lqbf = pow(base[-1], 2) + 1
    QBF = bitarray.bitarray(lqbf)  # This is our quasi-bloom-filter

    basej2N = powmod_base_list(base, 2, N)
    for p in basej2N: QBF[p] = 1

    for i in range(isqrt(N), N):
        i2N = powmod(i, 2, N)
        if i2N < lqbf and QBF[i2N] == 1:
            for k in range(0, len(base)):
                # if i2N == basej2N[k]: # this is replaced with a quasi-bloom-filter
                if QBF[basej2N[k]] == 1 and 1 < (f := gcd(i - base[k], N)) < N:
                    return f, N // f


def euler(n):
    """
    Euler factorization method is very much like fermat's
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

    k = pow(gcd(a - c, d - b), 2)
    h = pow(gcd(a + c, d + b), 2)
    m = pow(gcd(a + c, d - b), 2)
    l = pow(gcd(a - c, d + b), 2)

    return gcd(k + h, n), gcd(l + m, n)


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
    """
    Factor a x^y*x^z form integer with x prime.
    """
    power = 1
    max_power = (int(log(n) / log(base)) + 1) >> 1
    while power <= max_power:
        p = next_prime(base ** power)
        if is_divisible(n, p):
            return p, n // p
        power += 1


def fermat(n):
    if is_congruent(n, 2, 4):
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
    it does not contemplate k<3
    """
    a = 1
    t = 3
    while t < k:
        t = min(k, (t << 1) - 2)
        a = (a * (3 - (a * a) * n) >> 1) & ((1 << t) - 1)
    return inv_mod_pow_of_2(a, k)


def FactorHighAndLowBitsEqual(n, middle_bits=3):
    """
    Code taken and heavy modified from https://github.com/google/paranoid_crypto/blob/main/paranoid_crypto/lib/rsa_util.py
    Licensed under open source Apache License Version 2.0, January 2004.
    """
    if (n.bit_length() < 6) or (n % 8 != 1):
        return None
    k = (n.bit_length() + 1) >> 1
    r0 = InverseInverseSqrt2exp(n, k + 1)
    if r0 is None:
        raise ArithmeticError("expecting that square root exists")
    a = isqrt(n - 1) + 1
    for r in [r0, (1 << k) - r0]:
        s = a
        for i in range(k):
            if ((s ^ r) >> i) & 1:
                m = min(middle_bits, i)
                for _ in range(1 << m):
                    s += 1 << (i - m)
                    d = (s * s) - n
                    if is_square(d):
                        d_sqrt = isqrt(d)
                        return (s - d_sqrt, s + d_sqrt)
    return None


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
                                % (N, res, res_n,)
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
        k, x2 = 1, x * x
        y2 = x2 - n
        while y2 >= 0:
            if is_square(y2):
                y = isqrt(y2)
                z, w = x + y, x - y
                if z % n != 0 and w % n != 0:
                    return gcd(z, n), gcd(w, n)
            k += 1
            y2 = x2 - k * n
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
    if is_congruent(n, 2, 4):
        raise FactorizationError
    y = 1
    while not is_square(n + y ** 2):
        y += 1
    x = isqrt(n + y ** 2)
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

    for j in tqdm(range(Limit, 1, -1), disable=(not progress)):
        q = edqm1 // j + 1
        if q & part_q == part_q:
            break

    if n > q and n % q == 0:
        return q, n // q

    for k in tqdm(range(1, Limit, 1), disable=(not progress)):
        p = edpm1 // k + 1
        if gcd(p, q) == 1 and invmod(q, p) == qi:
            break

    print(f"p = {str(p)}", k)
    print(f"q = {str(q)}", j)
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
        if (g := gcd(n, a)) != 1: return g, n // g
        for r in range(2, n, 2):  # from this step is that it shoul be run in a quantum computer, but we are doing a linear search.
            if (ar := powmod(a, r, n)) == 1:  # ar is the period returned by the quantum computer, we are just bruteforcing it.
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

    if is_congruent(N, 2, 4):
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
