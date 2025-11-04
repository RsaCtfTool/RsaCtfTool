#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from RsaCtfTool.attacks.abstract_attack import AbstractAttack
from RsaCtfTool.lib.exceptions import FactorizationError
from RsaCtfTool.lib.algos import dixon


class Attack(AbstractAttack):
    def __init__(self, timeout=60):
        super().__init__(timeout)
        self.speed = AbstractAttack.speed_enum["slow"]

    def attack(self, publickey, cipher=[], progress=True):
        """Run dixon attack with a timeout"""
        try:
            if publickey.n <= 10_000_000_000:
                publickey.p, publickey.q = dixon(publickey.n)
            else:
                self.logger.error("[-] Dixon is too slow for pubkeys > 10^10...")
                return None, None

        except FactorizationError:
            return None, None

        return self.create_private_key(publickey)

    def test(self):
        from RsaCtfTool.lib.keys_wrapper import PublicKey

        key_data = """-----BEGIN PUBLIC KEY-----
MCAwDQYJKoZIhvcNAQEBBQADDwAwDAIFAQAwAjcCAwEAAQ==
-----END PUBLIC KEY-----"""
        result = self.attack(PublicKey(key_data), progress=False)
        return result != (None, None)
