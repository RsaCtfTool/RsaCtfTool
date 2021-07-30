#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from attacks.abstract_attack import AbstractAttack
from lib.rsalibnum import gcd, common_modulus
from Crypto.Util.number import long_to_bytes, bytes_to_long
import itertools

class Attack(AbstractAttack):
    def __init__(self, timeout=60):
        super().__init__(timeout)
        self.speed = AbstractAttack.speed_enum["fast"]

    def common_modulus_attack(self, c1, c2, k1, k2):
        if k1.n != k2.n:
            return None

        if gcd(k1.e, k2.e) != 1:
            return None

        deciphered_message = common_modulus(k1.e, k2.e, k1.n, c1, c2)
        return long_to_bytes(deciphered_message)

    def attack(self, publickeys, cipher=[]):
        """Common modulus attack"""
        if len(publickeys) < 2:
            return (None, None)
        if len(cipher) < 2:
            return (None, None)

        plains = []
        for k1, k2 in itertools.combinations(publickeys, 2):
            for c1, c2 in itertools.combinations(cipher, 2):
                plains.append(self.common_modulus_attack(c1, c2, k1, k2))

        if all([_ == None for _ in plains]):
            plains = None

        return (None, plains)
