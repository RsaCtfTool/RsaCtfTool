#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from attacks.abstract_attack import AbstractAttack
from lib.number_theory import gcd
from lib.utils import s2n
from lib.keys_wrapper import PrivateKey


class Attack(AbstractAttack):
    def __init__(self, timeout=60):
        super().__init__(timeout)
        self.speed = AbstractAttack.speed_enum["medium"]

    def comfact(self, cipher, publickey):
        for c in cipher:
            commonfactor = gcd(publickey.n, s2n(c))

            if commonfactor > 1:
                publickey.q = commonfactor
                publickey.p = publickey.n // publickey.q
                priv_key = PrivateKey(
                    int(publickey.p),
                    int(publickey.q),
                    int(publickey.e),
                    int(publickey.n),
                )
                return (priv_key, None)
        return (None, None)

    def attack(self, publickey, cipher=[], progress=True):
        """Try an attack where the public key has a common factor with the ciphertext - sourcekris"""
        return self.comfact(cipher, publickey) if cipher is not None else (None, None)

    def test(self):
        """FIXME: Implment testcase"""
        raise NotImplementedError
