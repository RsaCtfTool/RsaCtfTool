#!/usr/bin/env sage

# reference https://github.com/comaeio/OPCDE/blob/master/2017/15%20ways%20to%20break%20RSA%20security%20-%20Renaud%20Lifchitz/opcde2017-ds-lifchitz-break_rsa.pdf

import sys


def factor(n):
    import os
    # Add root to sys path so we can import RsaCtfTool
    rootpath = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    if rootpath not in sys.path:
        sys.path.append(rootpath)
        
    from RsaCtfTool.lib.coppersmith import CoppersmithParameters, _select_coppersmith_parameters
    from sage.coppersmith import coppersmith_univariate_sage

    depth = 50
    x = PolynomialRing(Zmod(n), "x").gen()

    for den in IntegerRange(2, depth + 1):
        for num in IntegerRange(1, den):
            if gcd(num, den) == 1:
                r = den / num
                phint = isqrt(n * r)
                f = x - phint
                
                # smallfraction originally used small_roots(beta=0.5)
                # the default X in Sage for beta=0.5 is N^(1/4)
                X = Integer(n ** 0.25)
                cands = _select_coppersmith_parameters(f.degree(), n, beta=0.5, X=X)
                if cands:
                    m, t = cands[0]
                    params = CoppersmithParameters(beta=0.5, X=X, m=m, t=t)
                    try:
                        sr = coppersmith_univariate_sage(f, n, params)
                        if len(sr) > 0:
                            p = phint - sr[0]
                            p = p.lift()
                            if n % p == 0:
                                return p
                    except Exception:
                        pass


try:
    n = int(sys.argv[1])
    p = factor(n)
    if p is None:
        print(0)
    else:
        print(p)
except:
    print(0)
