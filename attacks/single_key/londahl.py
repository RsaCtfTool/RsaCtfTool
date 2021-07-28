#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from attacks.abstract_attack import AbstractAttack
from tqdm import tqdm
from lib.rsalibnum import isqrt, invmod, trivial_factorization_with_n_phi
from lib.keys_wrapper import PrivateKey
from lib.utils import timeout, TimeoutError
from gmpy2 import powmod


class Attack(AbstractAttack):
    def __init__(self, timeout=60):
        super().__init__(timeout)
        self.speed = AbstractAttack.speed_enum["slow"]

    def close_factor(self, n, b, progress=True):
        # approximate phi
        phi_approx = n - 2 * isqrt(n) + 1

        # create a look-up table
        look_up = {}
        z = 1
        for i in tqdm(range(0, b + 1), disable=(not progress)):
            look_up[z] = i
            z = (z << 1) % n

        # check the table
        mu = invmod(powmod(2, phi_approx, n), n)
        fac = powmod(2, b, n)

        for i in tqdm(range(0, b + 1), disable=(not progress)):
            if mu in look_up:
                phi = phi_approx + (look_up[mu] - (i * b))
                r = trivial_factorization_with_n_phi(n, phi)
                if r != None:
                    return r
            mu = (mu * fac) % n
        else:
            return None

    def attack(self, publickey, cipher=[], progress=True):
        """Do nothing, used for multi-key attacks that succeeded so we just print the
        private key without spending any time factoring
        """
        londahl_b = 20000000
        with timeout(self.timeout):
            try:
                factors = self.close_factor(publickey.n, londahl_b, progress)

                if factors is not None:
                    p, q = factors
                    priv_key = PrivateKey(
                        int(p), int(q), int(publickey.e), int(publickey.n)
                    )
                    return (priv_key, None)
                else:
                    return (None, None)
            except TimeoutError:
                return (None, None)
        return (None, None)

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
