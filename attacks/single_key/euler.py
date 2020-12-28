# /usr/bin/env python
# code taken from https://maths.dk/teaching/courses/math357-spring2016/projects/factorization.pdf

import sys
from gmpy2 import *
from lib.utils import timeout, TimeoutError


def euler(n):
    if n % 2 == 0:
        return (n / 2, 2) if n > 2 else (2, 1)
    factors = (n, 1)
    end = isqrt(n)
    a = 0
    solutionsFound = []
    firstb = -1
    while a < end and len(solutionsFound) < 2:
        bsquare = n - a ** 2
        if bsquare > 0:
            b = isqrt(bsquare)
            if (b ** 2 == bsquare) and (a != firstb) and (b != firstb):
                firstb = b
                solutionsFound.append([int(b), a])
        a += 1
    if len(solutionsFound) < 2:
        print(str(n) + "is of the form 4k+3")
        return -1
    print("SolutionsFound:" + str(solutionsFound))
    a = solutionsFound[0][0]
    b = solutionsFound[0][1]
    c = solutionsFound[1][0]
    d = solutionsFound[1][1]
    print("aˆ2+bˆ2:" + str(a ** 2 + b ** 2) + "=cˆ2+dˆ2:" + str(c ** 2 + d ** 2))
    k = gcd(a - c, d - b)
    h = gcd(a + c, d + b)
    m = gcd(a + c, d - b)
    l = gcd(a - c, d + b)
    n = (k ** 2 + h ** 2) * (l ** 2 + m ** 2)
    print(n / 4)
    print(k, h, m, l)
    return [int(k ** 2 + h ** 2) // 2, int(l ** 2 + m ** 2) // 2]


def attack(attack_rsa_obj, publickey, cipher=[]):
    """Run attack with Euler method"""
    if not hasattr(publickey, "p"):
        publickey.p = None
    if not hasattr(publickey, "q"):
        publickey.q = None

    # Euler attack
    with timeout(attack_rsa_obj.args.timeout):
        try:
            try:
                euler_res = euler(publickey.n)
            except:
                print("Euler: Internal Error")
                return (None, None)
            if euler_res and len(euler_res) > 1:
                publickey.p, publickey.q = euler_res

            if publickey.q is not None:
                priv_key = PrivateKey(
                    int(publickey.p),
                    int(publickey.q),
                    int(publickey.e),
                    int(publickey.n),
                )
                return (priv_key, None)
        except TimeoutError:
            return (None, None)

    return (None, None)
