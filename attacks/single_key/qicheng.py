#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import logging
from lib.keys_wrapper import PrivateKey

__SAGE__ = True

logger = logging.getLogger("global_logger")


def factor(n):
    r""" Try to factor n using Qi Cheng's elliptic curve algorithm and return the result.

    TESTS::
        sage: factor(8586738020906178596816665408975869027249332195806516889218842326669979457567897544415936583733118068451112024495528372623268891464850844330698707082078341676048316328425781368868164458486632570090121972627446596326046274266659293352906034163997023314644106659615348855576648233885381655772208214809201687506171743157882478565146018301168224250821080109298362928393693620666868337500513217122524859198701942611835138196019213020523307383514277039557237260096859973)
        134826985114673693079697889309176855021348273420672992955072560868299506854125722349531357991805652015840085409903545018244092326610812466869635572979633488227724165641914777716235431963802791410179554688486108196212276141821415175590671132382956670453821994294396707908761669407050042067400072453975327507467

        sage: factor(1444329727510154393553799612747635457542181563961160832013134005088873165794135221)
        74611921979343086722526424506387128972933
    """
    import sys
    sys.setrecursionlimit(int(1e5))
    from sage.all import Integers, EllipticCurve, gcd

    R = Integers(n)
    attempts = 20
    js = [0, (-2**5)**3, (-2**5*3)**3, (-2**5*3*5*11)**3, (-2**6*3*5*23*29)**3]

    for _ in range(attempts):
        for j in js:
            if j == 0:
                a = R.random_element()
                E = EllipticCurve([0, a])

            else:
                a = R(j)/(R(1728)-R(j))
                c = R.random_element()
                E = EllipticCurve([3*a*c**2, 2*a*c**3])

            x = R.random_element()
            z = E.division_polynomial(n, x)
            g = gcd(z, n)
            if g > 1:
                return g
    return None


def attack(attack_rsa_obj, publickey, cipher=[]):
    """Qi Cheng - A New Class of Unsafe Primes
        """
        sageresult = factor(publickey.n)

        if sageresult is not None:
            p = sageresult
            q = publickey.n // sageresult
            priv_key = PrivateKey(int(p), int(q),
                                  int(publickey.e), int(publickey.n))
            return (priv_key, None)
        return (None, None)