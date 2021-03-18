#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from attacks.abstract_attack import AbstractAttack
import itertools
from lib.rsalibnum import gcd
from lib.keys_wrapper import PrivateKey
from lib.utils import timeout, TimeoutError


class Attack(AbstractAttack):
    def __init__(self, attack_rsa_obj, timeout=60):
        super().__init__(attack_rsa_obj, timeout)
        self.speed = AbstractAttack.speed_enum["fast"]

    def attack(self, publickeys, cipher=[]):
        """Common factor attack"""
        if not isinstance(publickeys, list):
            return (None, None)

        with timeout(self.timeout):
            try:
                # Try to find the gcd between each pair of moduli and resolve the private keys if gcd > 1
                priv_keys = []
                for x, y in itertools.combinations(publickeys, r=2):
                    if x.n != y.n:
                        g = gcd(x.n, y.n)
                        if g != 1:

                            try:
                                # update each attackobj with a private_key
                                x.p = g
                                x.q = x.n // g
                                y.p = g
                                y.q = y.n // g
                                priv_key_1 = PrivateKey(
                                    int(x.p), int(x.q), int(x.e), int(x.n)
                                )
                                priv_key_2 = PrivateKey(
                                    int(y.p), int(y.q), int(y.e), int(y.n)
                                )
                                priv_keys.append(priv_key_1)
                                priv_keys.append(priv_key_2)

                                self.logger.info(
                                    "[*] Found common factor in modulus for "
                                    + x.filename
                                    + " and "
                                    + y.filename
                                )
                            except ValueError:
                                continue
            except TimeoutError:
                return (None, None)

        priv_keys = list(set(priv_keys))
        if len(priv_keys) == 0:
            priv_keys = None

        return (priv_keys, None)
