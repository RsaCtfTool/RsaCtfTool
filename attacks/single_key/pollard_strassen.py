#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from attacks.abstract_attack import AbstractAttack
from lib.keys_wrapper import PrivateKey
from lib.exceptions import FactorizationError
from lib.algos import pollard_strassen


class Attack(AbstractAttack):
    def __init__(self, timeout=60):
        super().__init__(timeout)
        self.speed = AbstractAttack.speed_enum["medium"]

    def attack(self, publickey, cipher=[], progress=True):
        """Run pollard_strassen attack with a timeout"""
        try:
            publickey.p, publickey.q = pollard_strassen(publickey.n)
        except FactorizationError:
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
MCkwDQYJKoZIhvcNAQEBBQADGAAwFQIOMU3GRI2TOMFbCgAAAAkCAwEAAQ==
-----END PUBLIC KEY-----"""
        result = self.attack(PublicKey(key_data), progress=False)
        return result != (None, None)
