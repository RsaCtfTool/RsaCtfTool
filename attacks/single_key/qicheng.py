#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from attacks.abstract_attack import AbstractAttack
import subprocess
from lib.keys_wrapper import PrivateKey
from lib.utils import rootpath


class Attack(AbstractAttack):
    def __init__(self, attack_rsa_obj, timeout=60):
        super().__init__(attack_rsa_obj, timeout)
        self.speed = AbstractAttack.speed_enum["medium"]
        self.sage_required = True

    def attack(self, publickey, cipher=[]):
        """Qi Cheng - A New Class of Unsafe Primes"""
        try:
            sageresult = int(
                subprocess.check_output(
                    ["sage", "%s/sage/qicheng.sage" % rootpath, str(publickey.n)],
                    timeout=self.timeout,
                    stderr=subprocess.DEVNULL,
                )
            )
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired, ValueError):
            return (None, None)

        if sageresult > 0:
            p = sageresult
            q = publickey.n // sageresult
            priv_key = PrivateKey(int(p), int(q), int(publickey.e), int(publickey.n))
            return (priv_key, None)
        else:
            return (None, None)

    def test(self):
        from lib.keys_wrapper import PublicKey

        key_data = """-----BEGIN PUBLIC KEY-----
MIGeMA0GCSqGSIb3DQEBAQUAA4GMADCBiAKBgAf9o7hkl15GaKWJ51ULnccQmgKl
u1DS4UUpfTP9rVsJ0id9WMZeAD6sr2kJuraVywHszS4BNhYGfJ4Yyd+DabTpIWRx
zSdsZXTLCf5XvPV9BUkg9FCkBjvl0YBUZ1toQCUqlI6v0tGrEGllpUF3Nq67Htd1
YYO3FuEbderGwu9dAgMBAAE=
-----END PUBLIC KEY-----"""
        self.timeout = 120
        result = self.attack(PublicKey(key_data))
        return result != (None, None)
