#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from attacks.abstract_attack import AbstractAttack
from tqdm import tqdm
from lib.keys_wrapper import PrivateKey
from lib.utils import timeout, TimeoutError
from gmpy2 import gcd, next_prime


class Attack(AbstractAttack):
    def __init__(self, attack_rsa_obj, timeout=60):
        super().__init__(attack_rsa_obj, timeout)
        self.speed = AbstractAttack.speed_enum["medium"]

    def attack(self, publickey, cipher=[]):
        """Run tests against primorial +-1 composites"""
        with timeout(self.timeout):
            try:
                limit = 10000
                prime = 1
                primorial = 1
                p = q = None
                for x in tqdm(range(0, limit)):
                    prime = next_prime(prime)
                    primorial *= prime
                    primorial_p1 = [primorial - 1, primorial + 1]
                    g0, g1 = gcd(primorial_p1[0], publickey.n), gcd(
                        primorial_p1[1], publickey.n
                    )
                    if 1 < g0 < publickey.n:
                        p = publickey.n // g0
                        q = g0
                        break
                    if 1 < g1 < publickey.n:
                        p = publickey.n // g1
                        q = g1
                        break
                if p is not None and q is not None:
                    priv_key = PrivateKey(
                        int(p), int(q), int(publickey.e), int(publickey.n)
                    )
                    return (priv_key, None)
                return (None, None)
            except TimeoutError:
                return (None, None)


if __name__ == "__main__":
    attack = Attack()
    attack.test()