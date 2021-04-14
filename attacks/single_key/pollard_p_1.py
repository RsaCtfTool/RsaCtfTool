#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import math
from attacks.abstract_attack import AbstractAttack
from tqdm import tqdm
from lib.keys_wrapper import PrivateKey
from lib.utils import timeout, TimeoutError
from gmpy2 import gcd, isqrt, next_prime

class Attack(AbstractAttack):
    def __init__(self, timeout=60):
        super().__init__(timeout)
        self.speed = AbstractAttack.speed_enum["medium"]

    def pollard_P_1(self, n, progress=True):
        """Pollard P1 implementation"""
        z = []
        
        def first_primes(n):
           p = 2
           tmp = [p]
           while p <= n-1:
             p = next_prime(p)
             tmp.append(p)
           return tmp
        
        prime = first_primes(997)

        B1 = isqrt(n)
        for j in range(0, len(prime)):
            for i in range(1, int(math.log(B1) / math.log(prime[j])) + 1):
                z.append(prime[j])

        try:
            for pp in tqdm(prime, disable=(not progress)):
                i = 0
                x = pp
                while 1:
                    x = pow(x, z[i], n)
                    i = i + 1
                    y = gcd(n, x - 1)
                    if y != 1:
                        p = y
                        q = n // y
                        return p, q
                    if i >= len(z):
                        return 0, None
        except TypeError:
            return 0, None

    def attack(self, publickey, cipher=[], progress=True):
        """Run attack with Pollard P1"""
        if not hasattr(publickey, "p"):
            publickey.p = None
        if not hasattr(publickey, "q"):
            publickey.q = None

        with timeout(self.timeout):
            try:
                # Pollard P-1 attack
                try:
                    poll_res = self.pollard_P_1(publickey.n, progress)
                except RecursionError:
                    return (None, None)
                if poll_res and len(poll_res) > 1:
                    publickey.p, publickey.q = poll_res

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

    def test(self):
        from lib.keys_wrapper import PublicKey

        key_data = """-----BEGIN PUBLIC KEY-----
MBswDQYJKoZIhvcNAQEBBQADCgAwBwICCg0CAQM=
-----END PUBLIC KEY-----"""
        result = self.attack(PublicKey(key_data), progress=False)
        return result != (None, None)
