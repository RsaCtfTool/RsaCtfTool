#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from lib.keys_wrapper import PrivateKey

__SAGE__ = True

from lib.timeout import timeout


def factor(n):
    """reference
       https://github.com/comaeio/OPCDE/blob/master/2017/15%20ways%20to%20break%20RSA%20security%20-%20Renaud%20Lifchitz/opcde2017-ds-lifchitz-break_rsa.pdf
    """
    from sage.all import PolynomialRing, Zmod, IntegerRange, gcd, isqrt

    depth = 50
    x = PolynomialRing(Zmod(n), "x").gen()

    for den in IntegerRange(2, depth + 1):
        for num in IntegerRange(1, den):
            if gcd(num, den) == 1:
                r = den / num
                phint = isqrt(n * r)
                f = x - phint
                sr = f.small_roots(beta=0.5)

                if len(sr) > 0:
                    p = phint - sr[0]
                    p = p.lift()
                    if n % p == 0:
                        return p
    return None


def attack(attack_rsa_obj, publickey, cipher=[]):
    """Code/idea from Renaud Lifchitz's talk 15 ways to break RSA security @ OPCDE17
       only works if the sageworks() function returned True
    """

    with timeout(seconds=attack_rsa_obj.args.timeout):
        sageresult = factor(publickey.n)
        if sageresult is not None:
            publickey.p = sageresult
            publickey.q = publickey.n // publickey.p
            priv_key = PrivateKey(
                int(publickey.p), int(publickey.q), int(publickey.e), int(publickey.n)
            )
            return (priv_key, None)
    return (None, None)
