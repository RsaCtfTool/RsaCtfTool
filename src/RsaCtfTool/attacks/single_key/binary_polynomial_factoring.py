#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import ast
import subprocess

from RsaCtfTool.attacks.abstract_attack import AbstractAttack, SAGE_MIN_TIMEOUT
from RsaCtfTool.lib.utils import rootpath


class Attack(AbstractAttack):
    def __init__(self, timeout=60):
        super().__init__(max(timeout, SAGE_MIN_TIMEOUT))
        self.speed = AbstractAttack.speed_enum["slow"]
        self.required_binaries = ["sage"]
        self.required_scripts = ["sage/binary_polynomial_factoring.sage"]

    def attack(self, publickey, cipher=[], progress=True):
        """binary polynomial factoring"""
        try:
            output = subprocess.check_output(
                [
                    "sage",
                    f"{rootpath}/sage/binary_polynomial_factoring.sage",
                    str(publickey.n),
                ],
                timeout=self.timeout,
                stderr=subprocess.DEVNULL,
                text=True,
            )
            factors = ast.literal_eval(output.strip())
            p = next(
                int(factor)
                for factor in factors
                if 1 < int(factor) < publickey.n
                and publickey.n % int(factor) == 0
            )
        except (
            subprocess.CalledProcessError,
            subprocess.TimeoutExpired,
            StopIteration,
            SyntaxError,
            TypeError,
            ValueError,
        ):
            return (None, None)

        q = publickey.n // p
        return self.create_private_key_from_pqe(p, q, publickey.e, publickey.n)

    def test(self):
        from RsaCtfTool.lib.keys_wrapper import PublicKey

        # p and q each have 8 set bits, chosen so that multiplying them
        # never carries: n's bit polynomial is then poly(p) * poly(q).
        key_data = """-----BEGIN PUBLIC KEY-----
MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBEAQAAMAwAAABAAAADIAgAAACAIEAKAAc
BYAoAAAAcAWZBQAGDCAFQAEAAQEkCAAAABkgIQAgAIEIAAgAAACBAIECAwEAAQ==
-----END PUBLIC KEY-----"""
        result = self.attack(PublicKey(key_data), progress=False)
        return result != (None, None)
