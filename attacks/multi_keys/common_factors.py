#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from attacks.abstract_attack import AbstractAttack
from lib.rsalibnum import gcd
from lib.keys_wrapper import PrivateKey
from lib.utils import timeout, TimeoutError
from gmpy2 import mul


def ProductTree(s):
    l = len(s)
    while l > 1:
        if l & 1 != 0:
            s += [1]
            l += 1
        s = list(map(mul, s[0 : l >> 1], s[l >> 1 :]))
        l = len(s)
    return s[0]


class Attack(AbstractAttack):
    def __init__(self, timeout=60):
        super().__init__(timeout)
        self.speed = AbstractAttack.speed_enum["fast"]

    def attack(self, publickeys, cipher=[]):
        """Common factor attack"""
        if not isinstance(publickeys, list):
            return (None, None)

        with timeout(self.timeout):
            try:
                pubs = [pub.n for pub in publickeys]
                # Try to find the gcd between each pair of moduli and resolve the private keys if gcd > 1
                priv_keys = []
                M = ProductTree(pubs)
                for i in range(0, len(pubs) - 1):
                    pub = pubs[i]
                    x = publickeys[i]
                    R = M // pub
                    g = gcd(pub, R)
                    if pub > g > 1:
                        try:
                            p = g
                            q = pub // g
                            x.p = p
                            x.q = q
                            # update each attackobj with a private_key
                            priv_key_1 = PrivateKey(
                                int(x.p), int(x.q), int(x.e), int(x.n)
                            )
                            priv_keys.append(priv_key_1)

                            self.logger.info(
                                "[*] Found common factor in modulus for " + x.filename
                            )
                        except ValueError:
                            continue
            except TimeoutError:
                return (None, None)

        priv_keys = list(set(priv_keys))
        if len(priv_keys) == 0:
            priv_keys = None

        return (priv_keys, None)
