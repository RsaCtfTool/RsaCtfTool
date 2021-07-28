#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from attacks.abstract_attack import AbstractAttack
from lib.keys_wrapper import PrivateKey
from lib.exceptions import FactorizationError
from lib.utils import timeout, TimeoutError
from lib.rsalibnum import isqrt


class Attack(AbstractAttack):
    def __init__(self, timeout=60):
        super().__init__(timeout)
        self.speed = AbstractAttack.speed_enum["medium"]

    # Source - http://stackoverflow.com/a/20465181

    def fermat(self, n):
        """Fermat attack"""
        a = b = isqrt(n)
        b2 = pow(a, 2) - n
        while pow(b, 2) != b2:
            a += 1
            b2 = pow(a, 2) - n
            b = isqrt(b2)
        p, q = (a + b), (a - b)
        assert n == p * q
        return p, q

    def attack(self, publickey, cipher=[], progress=True):
        """Run fermat attack with a timeout"""
        try:
            with timeout(seconds=self.timeout):
                try:
                    publickey.p, publickey.q = self.fermat(publickey.n)
                except TimeoutError:
                    return (None, None)

        except FactorizationError:
            return (None, None)

        if publickey.p is not None and publickey.q is not None:
            try:
                priv_key = PrivateKey(
                    n=publickey.n,
                    p=int(publickey.p),
                    q=int(publickey.q),
                    e=int(publickey.e),
                )
                return (priv_key, None)
            except ValueError:
                return (None, None)

        return (None, None)

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
