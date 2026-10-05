#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import subprocess
from RsaCtfTool.attacks.abstract_attack import AbstractAttack, SAGE_MIN_TIMEOUT
from RsaCtfTool.lib.utils import rootpath


class Attack(AbstractAttack):
    def __init__(self, timeout=60):
        super().__init__(max(timeout, SAGE_MIN_TIMEOUT))
        self.speed = AbstractAttack.speed_enum["slow"]
        self.required_binaries = ["sage"]
        self.required_scripts = ["sage/smallfraction.sage"]

    def attack(self, publickey, cipher=[], progress=True):
        """Code/idea from RsaCtfTool.Renaud Lifchitz's talk 15 ways to break RSA security @ OPCDE17
        only works if the sageworks() function returned True
        """
        try:
            import shutil
            if shutil.which("sage"):
                r = subprocess.check_output(
                    ["sage", f"{rootpath}/sage/smallfraction.sage", str(publickey.n)],
                    timeout=self.timeout,
                    stderr=subprocess.DEVNULL,
                )
                try:
                    sageresult = int(r)
                except ValueError:
                    sageresult = 0
                if 1 < sageresult < publickey.n and publickey.n % sageresult == 0:
                    publickey.p = sageresult
                    publickey.q = publickey.n // publickey.p
                    return self.create_private_key_from_pqe(
                        publickey.p, publickey.q, publickey.e, publickey.n
                    )
                return (None, None)
            else:
                from RsaCtfTool.lib.algos import small_fraction
                p, q = small_fraction(publickey.n)
                
                if p is not None and q is not None:
                    publickey.p = p
                    publickey.q = q
                    return self.create_private_key_from_pqe(
                        publickey.p, publickey.q, publickey.e, publickey.n
                    )
        except Exception as exc:
            self.logger.error(f"[!] smallfraction attack failed: {exc}")
            
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
