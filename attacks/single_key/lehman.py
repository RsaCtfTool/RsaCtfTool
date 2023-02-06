#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from attacks.abstract_attack import AbstractAttack
from lib.keys_wrapper import PrivateKey
from lib.exceptions import FactorizationError
from lib.number_theory import isqrt, is_square, is_congruent, cuberoot, introot, gcd


def lehman(n):
    """
    based on: https://programmingpraxis.com/2017/08/22/lehmans-factoring-algorithm/
    """
    if is_congruent(n, 2, 4):
        raise FactorizationError

    for k in range(1, cuberoot(n)):
        nk4 = n * k << 2
        ki4 = isqrt(k) << 2
        ink4 = isqrt(nk4) + 1
        i6 = introot(n, 6)
        ink4i6ki4 = ink4 + (i6 // (ki4)) + 1
        for a in range(ink4, ink4i6ki4):
            b2 = (a * a) - nk4
            if is_square(b2):
                b = isqrt(b2)
                p = gcd(a + b, n)
                q = gcd(a - b, n)
                return p, q
    return []


class Attack(AbstractAttack):
    def __init__(self, timeout=60):
        super().__init__(timeout)
        self.speed = AbstractAttack.speed_enum["medium"]

    def attack(self, publickey, cipher=[], progress=True):
        """Run lehman attack with a timeout"""
        try:
            r = lehman(publickey.n)
            publickey.p, publickey.q = r

        except FactorizationError:
            self.logger.error("N should not be a 4k+2 number...")
            return None, None

        if publickey.p is not None and publickey.q is not None:
            try:
                priv_key = PrivateKey(
                    n=publickey.n,
                    p=int(publickey.p),
                    q=int(publickey.q),
                    e=int(publickey.e),
                )
                return priv_key, None
            except ValueError:
                return None, None

        return None, None

    def test(self):
        from lib.keys_wrapper import PublicKey

        key_data = """-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCG6ZYBPnfEFpkADglB1IDARrL3
Gk+Vs1CsGk1CY3KSPYpFYdlvv7AkBZWQcgGtMiXPbt7X3gLZHDhv+sKAty0Plcrn
H0Lr4NPtrqznzqMZX6MsHGCA2Q74U9Bt1Fcskrn4MQu8DGNaXiaVJRF1EDCmWQgW
VU52MDG8uzHj8RnGXwIDAQAB
-----END PUBLIC KEY-----"""
        result = self.attack(PublicKey(key_data), progress=False)
        return result != (None, None)
