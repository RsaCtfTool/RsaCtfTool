#!/usr/bin/sage
# Factoring integers representing them with polynomials with order=bits
# Ex: 15 = 2^0 + 2^1 + 2^2 + 2^3 -> (2^0 + 2^1) * (2^0 + 2^2) -> 3*5
# It works well with mersenne primes but not with other composites.

import sys
from gmpy2 import mpz
sys.setrecursionlimit(100000)


def int_to_poly(n):
    n = mpz(n)
    tmp = ""
    tmp2 = []
    bits = n.bit_length()
    for j in range(0, bits):
        b = int((n >> j) & 1)
        tmp = str(b) + tmp
        if b == 1:
            tmp2.append("x^%d " % (j))
    return "+".join(tmp2)


def factor_int(n, verbose=False):
    if verbose:
        print("converting to poly:")
    poly = SR(int_to_poly(n))
    if verbose:
        print(poly)
        print("finding factors:")
    factored = factor(poly)
    if verbose:
        print(factored)
        print("evaluating terms:")
    factors = []
    terms = str(factored).split(")*")
    ls = len(terms)
    if verbose:
        print(ls)
    if ls > 0:
        for term in terms:
            term = term.replace("(", "").replace(")", "")
            if verbose:
                print(term)
            factors.append(sage_eval(term, {'x': 2}))
    return factors

    if __name__ == "__main__":
        print(factor_int(Integer(sys.argv[1])))
