#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from RsaCtfTool.attacks.abstract_attack import AbstractAttack
from RsaCtfTool.lib.algos import lehmer_machine
from RsaCtfTool.lib.exceptions import FactorizationError


class Attack(AbstractAttack):
    def __init__(self, timeout=60):
        super().__init__(timeout)
        self.speed = AbstractAttack.speed_enum["medium"]

    def attack(self, publickey, cipher=[], progress=True):
        """Run lehmer_machine attack with a timeout"""
        try:
            publickey.p, publickey.q = lehmer_machine(publickey.n)
        except FactorizationError:
            self.logger.error("N should not be a 4k+2 number...")
            return None, None

        return self.create_private_key(publickey)

    def test(self):
        from RsaCtfTool.lib.keys_wrapper import PublicKey

        key_data = """-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCG6ZYBPnfEFpkADglB1IDARrL3
Gk+Vs1CsGk1CY3KSPYpFYdlvv7AkBZWQcgGtMiXPbt7X3gLZHDhv+sKAty0Plcrn
H0Lr4NPtrqznzqMZX6MsHGCA2Q74U9Bt1Fcskrn4MQu8DGNaXiaVJRF1EDCmWQgW
VU52MDG8uzHj8RnGXwIDAQAB
-----END PUBLIC KEY-----"""
        result = self.attack(PublicKey(key_data), progress=False)
        return result != (None, None)
