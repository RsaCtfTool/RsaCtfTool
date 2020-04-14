def londahl(self, londahl_b=20000000):
        # Another attack for primes that are too close together.
        # https://grocid.net/2017/09/16/finding-close-prime-factorizations/
        # `b` is the size of the lookup dictionary to build.
        try:
            import londahl
        except ImportError:
            print("[!] Warning: Londahl factorization module missing (londahl.py)")
            return

        factors = londahl.close_factor(self.pub_key.n, londahl_b)

        if factors is not None:
            self.pub_key.p, self.pub_key.q = factors
            self.priv_key = PrivateKey(int(self.pub_key.p), int(self.pub_key.q),
                                       int(self.pub_key.e), int(self.pub_key.n))

        return

#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import gmpy2

def close_factor(n, b):
 
    # approximate phi
    phi_approx = n - 2 * gmpy2.isqrt(n) + 1
 
    # create a look-up table
    look_up = {}
    z = 1
    for i in range(0, b + 1):
        look_up[z] = i
        z = (z * 2) % n
 
    # check the table
    mu = gmpy2.invert(pow(2, phi_approx, n), n)
    fac = pow(2, b, n)

    for i in range(0, b + 1):
        if mu in look_up:
            phi = phi_approx + (look_up[mu] - i * b)
            break
        mu = (mu * fac) % n
    else:
        return None
 
    m = n - phi + 1
    roots = (m - gmpy2.isqrt(m ** 2 - 4 * n)) // 2, \
            (m + gmpy2.isqrt(m ** 2 - 4 * n)) // 2
 
    assert roots[0] * roots[1] == n
    return roots

def attack(attack_rsa_obj, publickey, cipher=[]):
    """Do nothing, used for multi-key attacks that succeeded so we just print the
       private key without spending any time factoring
    """
    londahl_b=20000000
    factors = close_factor(publickey.n, londahl_b)

    if factors is not None:
        p, q = factors
        priv_key = PrivateKey(int(p), int(q),
                              int(publickey.e), int(publickey.n))
        return (priv_key, None)
    else:
        return (None, None)
