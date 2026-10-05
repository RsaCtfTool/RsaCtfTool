#!/usr/bin/sage -python

# by lwc
# source: https://raw.githubusercontent.com/lwcM/RSA_attack/master/partial_key_exposure_attack.py
# 2016/09/22
#
# Local fix: the original Coppersmith search bound X = 2^(nbits/2 - L) assumed
# the target factor has exactly half the bits of n. For a factor longer than
# that (or a leak slightly under the ideal size) the true root fell outside X
# and small_roots silently returned nothing. The bound is now swept over the
# plausible range; each call is cheap and lattice dimension does not depend on X.

import sys


def find_p_Coppersmith(n, pLow, lowerBitsNum, beta=0.5):
    x = PolynomialRing(Zmod(n), names='x').gen()
    nbits = n.bit_length()

    l = 1 << lowerBitsNum
    f = l * x + pLow
    f = f.monic()

    # Unknown high bits of the target factor range from (nbits//2 - L) when
    # the factor barely exceeds sqrt(n) up to (nbits - L) for a very
    # unbalanced factor. Sweep increasing bounds; Coppersmith's provable
    # window caps useful bounds at ~n^(beta^2 - epsilon) ~ 19% of nbits.
    lo = max((nbits >> 1) - lowerBitsNum, 4)
    hi = min(nbits - lowerBitsNum, (nbits * 19) // 100)
    if hi < lo:
        hi = lo
    bounds = list(range(lo, hi + 1, 8))
    if not bounds or bounds[-1] != hi:
        bounds.append(hi)

    import os, sys
    # Add root to sys path so we can import RsaCtfTool
    rootpath = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    if rootpath not in sys.path:
        sys.path.append(rootpath)
        
    from RsaCtfTool.lib.coppersmith import CoppersmithParameters, _select_coppersmith_parameters
    from sage.coppersmith import coppersmith_univariate_sage

    for ubits in bounds:
        X = 1 << ubits
        cands = _select_coppersmith_parameters(f.degree(), n, beta=beta, X=X)
        if cands:
            m, t = cands[0]
            params = CoppersmithParameters(beta=beta, X=X, m=m, t=t)
            try:
                roots = coppersmith_univariate_sage(f, n, params)
                if roots:
                    return [
                        int(r)
                        for r in [ZZ(gcd(l * x0 + pLow, n)) for x0 in roots]
                        if n > r > 1
                    ]
            except Exception:
                pass
    return None


def hensel_lift(a, b, c, bits):
    """
    Solve a*X^2 + b*X + c == 0 (mod 2^bits) using Hensel's lemma lifting.
    Returns a list of integer solutions in [0, 2^bits).
    """
    # Seed: solutions mod 2
    roots = [r for r in range(2) if (a * r * r + b * r + c) % 2 == 0]

    for k in range(1, bits):
        mod = 1 << k          # 2^k
        next_mod = mod << 1   # 2^(k+1)
        new_roots = []
        for r in roots:
            for delta in (0, mod):   # try r and r + 2^k
                candidate = r + delta
                val = a * candidate * candidate + b * candidate + c
                if val % next_mod == 0:
                    new_roots.append(candidate)
        roots = new_roots

    mod_final = 1 << bits
    return [r % mod_final for r in roots]


def find_p(n, e, dLow, beta=0.5):
    lowerBitsNum = dLow.bit_length()

    for k in range(1, e + 1):
        # Quadratic: k*X^2 + (e*dLow - k*(n+1) - 1)*X + k*n == 0 (mod 2^lowerBitsNum)
        a = k
        b = e * dLow - k * (n + 1) - 1
        c = k * n

        for pLow in hensel_lift(a, b, c, lowerBitsNum):
            pLow = ZZ(pLow)
            roots = find_p_Coppersmith(n, pLow, lowerBitsNum, beta)
            if roots:
                return roots[0]


def partial_d(n, e, dLow, beta=0.5):
    p = find_p(n, e, dLow, beta)
    assert p is not None and n % p == 0, 'fail'
    return p, n // p


beta = 0.5

n = int(sys.argv[1])
e = int(sys.argv[2])
dLow = int(sys.argv[3])

p, q = partial_d(n, e, dLow, beta)
print(p, q)
