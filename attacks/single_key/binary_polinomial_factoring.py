#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from attacks.abstract_attack import AbstractAttack
import subprocess
from lib.keys_wrapper import PrivateKey
from lib.utils import rootpath


class Attack(AbstractAttack):
    def __init__(self, timeout=60):
        super().__init__(timeout)
        self.speed = AbstractAttack.speed_enum["slow"]
        self.required_binaries = ["sage"]

    def attack(self, publickey, cipher=[], progress=True):
        """binary polinomial factoring"""
        try:
            sageresult = str(
                subprocess.check_output(
                    [
                        "sage",
                        f"{rootpath}/sage/binary_polinomial_factoring.sage",
                        str(publickey.n),
                    ],
                    timeout=self.timeout,
                    stderr=subprocess.DEVNULL,
                )
            ).split(" ")

        except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
            return (None, None)

        try:
            p = int(sageresult[0])
        except ValueError:
            return (None, None)

        if p > 0:
            q = publickey.n // p
            priv_key = PrivateKey(p, int(q), int(publickey.e), int(publickey.n))
            return (priv_key, None)
        else:
            return (None, None)
