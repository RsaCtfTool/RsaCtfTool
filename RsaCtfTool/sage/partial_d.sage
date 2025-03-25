#!/usr/bin/sage -python

# by lwc
# source: https://raw.githubusercontent.com/lwcM/RSA_attack/master/partial_key_exposure_attack.py
# 2016/09/22

import sys


def find_p_Coppersmith(n, pLow, lowerBitsNum, beta=0.5):
    x = PolynomialRing(Zmod(n), names='x').gen()
    nbits = n.bit_length()

    l = 1 << lowerBitsNum
    f = l * x + pLow
    f = f.monic()
    if (roots = f.small_roots(X = 1 << ((nbits >> 1) - lowerBitsNum), beta=beta)):
        return [int(r) for r in [ ZZ(gcd(l * x0 + pLow, n)) for x0 in roots ] if n > r > 1]


def find_p(n, e, dLow, beta=0.5):
    X = var('X')
    lowerBitsNum = dLow.bit_length()

    edX = e * dLow * X
    XnX1 = X * (n - X + 1)
    for k in range(1, e + 1):
        results = solve_mod([edX - (k * XnX1) + (k * n) == X], (1 << lowerBitsNum))
        for x in results:
            pLow = ZZ(x[0])
            if (roots := find_p_Coppersmith(n, pLow, lowerBitsNum)):
                return roots[0]


def partial_d(n, e, dLow, beta=0.5):
    p = find_p(n, e, dLow, beta)
    assert p is not None and n % p == 0, 'fail'
    return p, n // p


# n = 123541066875660402939610015253549618669091153006444623444081648798612931426804474097249983622908131771026653322601466480170685973651622700515979315988600405563682920330486664845273165214922371767569956347920192959023447480720231820595590003596802409832935911909527048717061219934819426128006895966231433690709
# e = 97
beta = 0.5
# dLow = 48553333005218622988737502487331247543207235050962932759743329631099614121360173210513133

n = int(sys.argv[1])
e = int(sys.argv[2])
dLow = int(sys.argv[3])

p, q = partial_d(n, e, dLow, beta)
print(p, q)
