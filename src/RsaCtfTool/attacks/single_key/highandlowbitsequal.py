#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from RsaCtfTool.attacks.abstract_attack import AbstractAttack
from RsaCtfTool.lib.keys_wrapper import PrivateKey
from RsaCtfTool.lib.algos import FactorHighAndLowBitsEqual


class Attack(AbstractAttack):
    def __init__(self, timeout=60):
        super().__init__(timeout)
        self.speed = AbstractAttack.speed_enum["medium"]

    def attack(self, publickey, cipher=[], progress=True):
        """Run FactorHighAndLowBitsEqual attack with a timeout"""

        try:
            pq = FactorHighAndLowBitsEqual(publickey.n)
        except:
            pq = None

        if pq is not None:
            publickey.p = pq[0]
            publickey.q = pq[1]

            priv_key = PrivateKey(
                n=publickey.n,
                p=int(publickey.p),
                q=int(publickey.q),
                e=int(publickey.e),
            )
            return priv_key, None

        return None, None

    def test(self):
        from RsaCtfTool.lib.keys_wrapper import PublicKey

        key_data = """-----BEGIN PUBLIC KEY-----
MDQwDQYJKoZIhvcNAQEBBQADIwAwIAIZAKGAon/dEGXmAuaZ0X1IIW2sUdRAh1ew
SQIDAQAB
-----END PUBLIC KEY-----"""
        result = self.attack(PublicKey(key_data), progress=False)
        return result != (None, None)
