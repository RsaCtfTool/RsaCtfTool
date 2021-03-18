#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from attacks.abstract_attack import AbstractAttack
from tqdm import tqdm
from lib.keys_wrapper import PrivateKey
from lib.utils import timeout, TimeoutError
from math import log2
from gmpy2 import gcd


class Attack(AbstractAttack):
    def __init__(self, attack_rsa_obj, timeout=60):
        super().__init__(attack_rsa_obj, timeout)
        self.speed = AbstractAttack.speed_enum["medium"]

    def attack(self, publickey, cipher=[]):
        """Run tests against mersenne composites"""
        with timeout(self.timeout):
            try:
                p = q = None
                for i in tqdm(range(2, int(log2(publickey.n)))):
                    i2 = 2 ** i
                    mersenne = [i2 - 1, i2 + 1]
                    g0, g1 = gcd(mersenne[0], publickey.n), gcd(
                        mersenne[1], publickey.n
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