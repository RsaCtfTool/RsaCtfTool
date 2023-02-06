#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from attacks.abstract_attack import AbstractAttack
from lib.keys_wrapper import PrivateKey
from lib.number_theory import getpubkeysz
from lib.is_roca_test import is_roca_vulnerable
from lib.external import neca_factor_driver
import logging


class Attack(AbstractAttack):
    def __init__(self, timeout=60):
        super().__init__(timeout)
        self.speed = AbstractAttack.speed_enum["slow"]
        self.logger = logging.getLogger("global_logger")
        self.required_binaries = ["neca", "sage"]

    def attack(self, publickey, cipher=[], progress=True):
        if is_roca_vulnerable(publickey.n):
            if getpubkeysz(publickey.n) <= 512:
                pq = neca_factor_driver(publickey.n, timeout=self.timeout)
                if pq is not None:
                    priv_key = PrivateKey(
                        int(pq[0]), int(pq[1]), int(publickey.e), int(publickey.n)
                    )
                    return (priv_key, None)
                else:
                    return (None, None)
            else:
                self.logger.error(
                    "[-] This key is roca but > 512 bits, try with roca attack..."
                )
                return (None, None)
        else:
            self.logger.error("[-] This key is not roca, skiping test...")
            return (None, None)

    def test(self):
        from lib.keys_wrapper import PublicKey

        key_data = """-----BEGIN PUBLIC KEY-----
MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAIAce1LytE5hd6Kl8yUMSo9BSfvjgW9W
3nu+QG7/FNRjB7+ot8giOYNZqid2e6Z/MrJf1QzftgJCF9qhUv2egKUCAwEAAQ==
-----END PUBLIC KEY-----"""
        self.timeout = 120
        result = self.attack(PublicKey(key_data), progress=False)
        return result != (None, None)
