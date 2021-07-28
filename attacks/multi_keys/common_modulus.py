#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from attacks.abstract_attack import AbstractAttack
from lib.rsalibnum import gcd
from Crypto.Util.number import long_to_bytes, bytes_to_long
import gmpy2

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

    def attack(self, publickeys, cipher=[]):
        """Common modulus attack"""
        if len(publickeys) != 2:
            self.logger.warning("[-] There must be two public keys")
            return (None, None)
        if len(cipher) != 2:
            self.logger.warning("[-] There must be two ciphertexts")
            return (None, None)

        self.logger.info("[+] Trying to find common modulus")

        if publickeys[0].n != publickeys[1].n:
            self.logger.warning(
                "[ERROR] The modulus of both public keys must be the same\n"
            )
            return (None, None)
        if gcd(publickeys[0].e, publickeys[1].e) != 1:
            self.logger.warning(
                "[ERROR] The greatest common denominator between the exponent of each keys should be 1\n"
            )
            return (None, None)
        deciphered_message = common_modulus(
            publickeys[0].e, publickeys[1].e, publickeys[0].n, cipher[0], cipher[1]
        )
        deciphered_bytes = long_to_bytes(deciphered_message)

        return (None, deciphered_bytes)