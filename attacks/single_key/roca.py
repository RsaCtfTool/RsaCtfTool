#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from attacks.abstract_attack import AbstractAttack
import subprocess
from lib.keys_wrapper import PrivateKey
from lib.utils import rootpath
from lib.is_roca_test import is_roca_vulnerable
import logging


class Attack(AbstractAttack):
    def __init__(self, timeout=60):
        super().__init__(timeout)
        self.speed = AbstractAttack.speed_enum["slow"]
        self.required_binaries = ["sage"]
        self.logger = logging.getLogger("global_logger")

    def attack(self, publickey, cipher=[], progress=True):
        if is_roca_vulnerable(publickey.n):
            try:
                sageresult = subprocess.check_output(
                    ["sage", f"{rootpath}/sage/roca_attack.py", str(publickey.n)],
                    timeout=self.timeout,
                    stderr=subprocess.DEVNULL,
                )

            except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
                return (None, None)

            if b"FAIL" not in sageresult and b":" in sageresult:
                sageresult = sageresult.decode("utf-8").strip()
                p, q = map(int, sageresult.split(":"))
                priv_key = PrivateKey(
                    int(p), int(q), int(publickey.e), int(publickey.n)
                )
                return (priv_key, None)
            else:
                return (None, None)
        else:
            self.logger.error("[-] This key is not roca, skiping test...")
            return (None, None)

    def test(self):
        from lib.keys_wrapper import PublicKey

        key_data = """-----BEGIN PUBLIC KEY-----
MFswDQYJKoZIhvcNAQEBBQADSgAwRwJAar8f96eVg1jBUt7IlYJk89ksQxJSdIjC
3e7baDh166JFr7lL6jrkD+9fsqgxFj9nPRYWCkKX/JcceVd5Y81YQwIDAQAB
-----END PUBLIC KEY-----"""
        self.timeout = 120
        result = self.attack(PublicKey(key_data), progress=False)
        return result != (None, None)
