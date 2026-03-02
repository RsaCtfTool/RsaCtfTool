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
            if (roots := find_p_Coppersmith(n, pLow, lowerBitsNum, beta)):
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
