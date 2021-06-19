#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from attacks.abstract_attack import AbstractAttack
import subprocess
from lib.keys_wrapper import PrivateKey
from lib.utils import rootpath
from lib.rsalibnum import getpubkeysz
from lib.is_roca_test import is_roca_vulnerable
import logging
import os
import re


class Attack(AbstractAttack):
    def __init__(self, timeout=60):
        super().__init__(timeout)
        self.speed = AbstractAttack.speed_enum["slow"]
        self.logger = logging.getLogger("global_logger")
        self.required_binaries = ["neca", "sage"]

    def attack(self, publickey, cipher=[], progress=True):
        if is_roca_vulnerable(publickey.n):
            if getpubkeysz(publickey.n) <= 512:
                necaresult = subprocess.check_output(
                    ["neca", "%s" % publickey.n],
                    timeout=self.timeout,
                    stderr=subprocess.DEVNULL,
                )
                necaresult_l = necaresult.decode("utf8").split("\n")
                if b"FAIL" not in necaresult and b"*" in necaresult:
                    for line in necaresult_l:
                        r0 = line.find("N = ")
                        r1 = line.find(" * ")
                        if r0 > -1 and r1 > -1:
                            p, q = list(map(int, line.split("=")[1].split("*")))
                            priv_key = PrivateKey(
                                int(p), int(q), int(publickey.e), int(publickey.n)
                            )
                            return (priv_key, None)
                else:
                    return (None, None)
            else:
                self.logger.info(
                    "[-] This key is roca but > 512 bits, try with roca attack..."
                )
                return (None, None)
        else:
            self.logger.info("[-] This key is not roca, skiping test...")
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
