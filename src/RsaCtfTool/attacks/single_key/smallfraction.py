#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import subprocess
from RsaCtfTool.attacks.abstract_attack import AbstractAttack
from RsaCtfTool.lib.utils import rootpath


class Attack(AbstractAttack):
    def __init__(self, timeout=60):
        super().__init__(timeout)
        self.speed = AbstractAttack.speed_enum["slow"]
        self.required_binaries = ["sage"]

    def attack(self, publickey, cipher=[], progress=True):
        """Code/idea from RsaCtfTool.Renaud Lifchitz's talk 15 ways to break RSA security @ OPCDE17
        only works if the sageworks() function returned True
        """
        try:
            r = subprocess.check_output(
                ["sage", f"{rootpath}/sage/smallfraction.sage", str(publickey.n)],
                timeout=self.timeout,
                stderr=subprocess.DEVNULL,
            )
            sageresult = int(r)
            if sageresult > 0:
                publickey.p = sageresult
                publickey.q = publickey.n // publickey.p
                return self.create_private_key_from_pqe(publickey.p, publickey.q, publickey.e, publickey.n)
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
            return (None, None)
        return (None, None)

    def test(self):
        from RsaCtfTool.lib.keys_wrapper import PublicKey

        key_data = """-----BEGIN PUBLIC KEY-----
MGYwDQYJKoZIhvcNAQEBBQADVQAwUgJLAi7v97hPb80NkMELBLYGAGEeDOdFAiW6
5wq4OGN1P6nmUmg5iFRQA6YWU8x1WdQMmVs6KxIUS89W0InUN3JVQ9SzLE32nKXc
t6rrAgMBAAE=
-----END PUBLIC KEY-----"""

        result = self.attack(PublicKey(key_data), progress=False)
        return result != (None, None)
