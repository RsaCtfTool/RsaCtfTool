#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from RsaCtfTool.attacks.abstract_attack import AbstractAttack
from RsaCtfTool.lib.exceptions import FactorizationError
from RsaCtfTool.lib.algos import carmichael


class Attack(AbstractAttack):
    def __init__(self, timeout=60):
        super().__init__(timeout)
        self.speed = AbstractAttack.speed_enum["medium"]

    def attack(self, publickey, cipher=[], progress=True):
        """Run carmichael attack with a timeout"""
        try:
            r = carmichael(publickey.n)
            publickey.p, publickey.q = r

        except FactorizationError:
            self.logger.error("N should not be a 4k+2 number...")
            return None, None

        return self.create_private_key(publickey)

    def test(self):
        from RsaCtfTool.lib.keys_wrapper import PublicKey

        key_data = """-----BEGIN PUBLIC KEY-----
MB8wDQYJKoZIhvcNAQEBBQADDgAwCwIEALpqqQIDAQAB
-----END PUBLIC KEY-----"""
        result = self.attack(PublicKey(key_data), progress=False)
        return result != (None, None)
