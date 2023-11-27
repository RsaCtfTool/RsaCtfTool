#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from attacks.abstract_attack import AbstractAttack
import subprocess
from lib.keys_wrapper import PrivateKey
from lib.utils import rootpath


class Attack(AbstractAttack):
    def __init__(self, timeout=60):
        super().__init__(timeout)
        self.speed = AbstractAttack.speed_enum["medium"]
        self.required_binaries = ["sage"]

    def attack(self, publickey, cipher=[], progress=True):
        """Qi Cheng - A New Class of Unsafe Primes"""
        try:
            sageresult = int(
                subprocess.check_output(
                    ["sage", f"{rootpath}/sage/qicheng.sage", str(publickey.n)],
                    timeout=self.timeout,
                    stderr=subprocess.DEVNULL,
                )
            )
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired, ValueError):
            return (None, None)

        if sageresult <= 0:
            return (None, None)
        q = publickey.n // sageresult
        priv_key = PrivateKey(sageresult, int(q), int(publickey.e), int(publickey.n))
        return (priv_key, None)

    def test(self):
        from lib.keys_wrapper import PublicKey

        key_data = """-----BEGIN PUBLIC KEY-----
MIGeMA0GCSqGSIb3DQEBAQUAA4GMADCBiAKBgAf9o7hkl15GaKWJ51ULnccQmgKl
u1DS4UUpfTP9rVsJ0id9WMZeAD6sr2kJuraVywHszS4BNhYGfJ4Yyd+DabTpIWRx
zSdsZXTLCf5XvPV9BUkg9FCkBjvl0YBUZ1toQCUqlI6v0tGrEGllpUF3Nq67Htd1
YYO3FuEbderGwu9dAgMBAAE=
-----END PUBLIC KEY-----"""
        self.timeout = 120
        result = self.attack(PublicKey(key_data), progress=False)
        return result != (None, None)
