#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from lib.number_theory import invert, chinese_remainder
from attacks.abstract_attack import AbstractAttack
from functools import reduce


class Attack(AbstractAttack):
    def __init__(self, timeout=60):
        super().__init__(timeout)
        self.speed = AbstractAttack.speed_enum["medium"]


    def attack(self, publickeys, cipher=[], progress=True):
        """Hastad attack for low public exponent
        this has found success for e = 3
        """
        if not isinstance(publickeys, list):
            return None, None

        if cipher is None or len(cipher) == 0:
            return None, None

        c = []
        for _ in cipher:
            c.append(int.from_bytes(_, byteorder="big"))

        n = []
        e = []
        for publickey in publickeys:
            if publickey.e < 11:
                n.append(publickey.n)
                e.append(publickey.e)

        e = set(e)
        if len(e) != 1:
            return None, None
        e = e.pop()
        if e != 3:
            return None, None

        result = chinese_remainder(n, c)
        nth = invert(result, 3)

        unciphered = []
        unciphered.append(nth.to_bytes((nth.bit_length() + 7) // 8, byteorder="big"))

        try:
            unciphered_ = b""
            for i in range(0, len(str(nth)), 3):
                _ = str(nth)[i : i + 3]
                unciphered_ += bytes([int(_)])
            unciphered.append(unciphered_)
        except:
            return None, None

        return None, unciphered
