#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from attacks.abstract_attack import AbstractAttack
from lib.rsalibnum import gcd
from Crypto.Util.number import long_to_bytes, bytes_to_long
import gmpy2
import itertools

# Source: https://crypto.stackexchange.com/a/60404
def bytes_to_integer(data):
    output = 0
    size = len(data)
    for index in range(size):
        output |= data[index] << (8 * (size - 1 - index))
    return output


def integer_to_bytes(integer, _bytes):
    output = bytearray()
    for byte in range(_bytes):
        output.append((integer >> (8 * (_bytes - 1 - byte))) & 255)
    return output


# Source: https://github.com/ashutosh1206/Crypton/blob/master/RSA-encryption/Attack-Common-Modulus/exploit.py
def egcd(a, b):
    if a == 0:
        return (b, 0, 1)
    else:
        g, y, x = egcd(b % a, a)
        return (g, x - (b // a) * y, y)


# Calculates a^{b} mod n when b is negative
def neg_pow(a, b, n):
    assert b < 0
    assert gcd(a, n) == 1
    res = int(gmpy2.invert(a, n))
    res = pow(res, b * (-1), n)
    return res


# e1 --> Public Key exponent used to encrypt message m and get ciphertext c1
# e2 --> Public Key exponent used to encrypt message m and get ciphertext c2
# n --> Modulus
# The following attack works only when m^{GCD(e1, e2)} < n
def common_modulus(e1, e2, n, c1, c2):
    c1 = bytes_to_long(c1)
    c2 = bytes_to_long(c2)
    g, a, b = egcd(e1, e2)
    if a < 0:
        c1 = neg_pow(c1, a, n)
    else:
        c1 = pow(c1, a, n)
    if b < 0:
        c2 = neg_pow(c2, b, n)
    else:
        c2 = pow(c2, b, n)
    ct = c1 * c2 % n
    m = int(gmpy2.iroot(ct, g)[0])
    return m


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
