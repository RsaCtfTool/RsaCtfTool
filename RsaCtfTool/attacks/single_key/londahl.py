#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from attacks.abstract_attack import AbstractAttack
from tqdm import tqdm
from lib.keys_wrapper import PrivateKey
from lib.algos import close_factor


class Attack(AbstractAttack):
    def __init__(self, timeout=60):
        super().__init__(timeout)
        self.speed = AbstractAttack.speed_enum["slow"]

    def attack(self, publickey, cipher=[], progress=True):
        """Do nothing, used for multi-key attacks that succeeded so we just print the
        private key without spending any time factoring
        """
        londahl_b = 10000000
        factors = close_factor(publickey.n, londahl_b, progress)

        if factors is not None:
            p, q = factors
            priv_key = PrivateKey(int(p), int(q), int(publickey.e), int(publickey.n))
            return priv_key, None

        return None, None

    def test(self):
        from lib.keys_wrapper import PublicKey

        key_data = """-----BEGIN PUBLIC KEY-----
MIGeMA0GCSqGSIb3DQEBAQUAA4GMADCBiAKBgAOBxiQviVpL4G5d0TmVmjDn51zu
iravDlD4vUlVk9XK79/fwptVzYsjimO42+ZW5VmHF2AUXaPhDC3jBaoNIoa78CXO
ft030bR1S0hGcffcDFMm/tZxwu2/AAXCHoLdjHSwL7gxtXulFxbWoWOdSq+qxtak
zBSZ7R1QlDmbnpwdAgMDEzc=
-----END PUBLIC KEY-----"""
        self.timeout = 120
        result = self.attack(PublicKey(key_data), progress=False)
        return result != (None, None)
