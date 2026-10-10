#!/usr/bin/env python3

import subprocess

from RsaCtfTool.attacks.abstract_attack import SAGE_MIN_TIMEOUT, AbstractAttack
from RsaCtfTool.lib.coppersmith import CoppersmithError
from RsaCtfTool.lib.keys_wrapper import PublicKey
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
        except CoppersmithError as exc:
            if "Sage" in str(exc):
                self.logger.info("[!] smallfraction attack requires Sage dependency")
            else:
                self.logger.error(f"[!] smallfraction attack failed: {exc}")
            return (None, None)
        except (
            subprocess.CalledProcessError,
            subprocess.TimeoutExpired,
            TypeError,
            ValueError,
            FileNotFoundError,
        ) as exc:
            self.logger.error(f"[!] smallfraction attack failed: {exc}")
            
        return (None, None)

    def test(self):
        key_data = """-----BEGIN PUBLIC KEY-----
MGYwDQYJKoZIhvcNAQEBBQADVQAwUgJLAi7v97hPb80NkMELBLYGAGEeDOdFAiW6
5wq4OGN1P6nmUmg5iFRQA6YWU8x1WdQMmVs6KxIUS89W0InUN3JVQ9SzLE32nKXc
t6rrAgMBAAE=
-----END PUBLIC KEY-----"""

        result = self.attack(PublicKey(key_data), progress=False)
        return result != (None, None)
