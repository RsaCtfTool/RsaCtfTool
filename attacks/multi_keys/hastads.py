#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from attacks.abstract_attack import AbstractAttack
from functools import reduce
from lib.utils import timeout, TimeoutError


class Attack(AbstractAttack):
    def __init__(self, timeout=60):
        super().__init__(timeout)
        self.speed = AbstractAttack.speed_enum["medium"]

    def chinese_remainder(self, n, a):
        sum = 0
        prod = reduce(lambda a, b: a * b, n)

        for n_i, a_i in zip(n, a):
            p = prod // n_i
            sum += a_i * self.mul_inv(p, n_i) * p
        return sum % prod

    def mul_inv(self, a, b):
        b0 = b
        x0, x1 = 0, 1
        if b == 1:
            return 1
        while a > 1:
            q = a // b
            a, b = b, a % b
            x0, x1 = x1 - q * x0, x0
        if x1 < 0:
            x1 += b0
        return x1

    def find_invpow(self, x, n):
        high = 1
        while high ** n < x:
            high *= 2
        low = high >> 1
        while low < high:
            mid = (low + high) >> 1
            if low < mid and mid ** n < x:
                low = mid
            elif high > mid and mid ** n > x:
                high = mid
            else:
                return mid
        return mid + 1

    def attack(self, publickeys, cipher=[]):
        """Hastad attack for low public exponent
        this has found success for e = 3
        """
        if not isinstance(publickeys, list):
            return (None, None)

        if cipher is None or len(cipher) == 0:
            return (None, None)

        with timeout(self.timeout):
            try:
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
                    return (None, None)
                e = e.pop()
                if e != 3:
                    return (None, None)

                result = self.chinese_remainder(n, c)
                nth = self.find_invpow(result, 3)

                unciphered = []
                unciphered.append(
                    nth.to_bytes((nth.bit_length() + 7) // 8, byteorder="big")
                )

                try:
                    unciphered_ = b""
                    for i in range(0, len(str(nth)), 3):
                        _ = str(nth)[i : i + 3]
                        unciphered_ += bytes([int(_)])
                    unciphered.append(unciphered_)
                except:
                    return (None, None)

            except TimeoutError:
                return (None, None)

        return (None, unciphered)
