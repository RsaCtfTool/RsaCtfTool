#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from attacks.abstract_attack import AbstractAttack
from lib.keys_wrapper import PrivateKey
from lib.algos import factor_2PN


class Attack(AbstractAttack):
    def __init__(self, timeout=60):
        super().__init__(timeout)
        self.speed = AbstractAttack.speed_enum["medium"]

    def attack(self, publickey, cipher=[], progress=True):
        """Run factor (2P)N form attack with a timeout"""
        try:
            for z in [3, 5, 7, 11, 13, 17]:
                pq = factor_2PN(publickey.n, z)
                if pq != []:
                    publickey.p, publickey.q = pq
                    break

        except:
            self.logger.error("Internal factorization error...")
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
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQQBZxdhmWmnALU8TFXFgAAAAAAA
AAAAAAAAAAAAAAAAADYUNH0k0DAi1K2rOxXAAAAAAAAAAAAAAAAAAAAAAApBMx+c
xBXy+AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAuBWMwhWfi0AAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAIAGQIDAQAB
-----END PUBLIC KEY-----"""
        result = self.attack(PublicKey(key_data), progress=False)
        return result != (None, None)
