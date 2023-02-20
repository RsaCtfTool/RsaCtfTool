#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from attacks.abstract_attack import AbstractAttack
from tqdm import tqdm
from lib.number_theory import isqrt, invmod, trivial_factorization_with_n_phi
from lib.keys_wrapper import PrivateKey
from gmpy2 import powmod


def close_factor(n, b, progress=True):
    """
    source: https://web.archive.org/web/20201031000312/https://grocid.net/2017/09/16/finding-close-prime-factorizations/
    """
    # approximate phi
    phi_approx = n - 2 * isqrt(n) + 1
    # Create a look-up table
    # If phi_approx is odd we are going to search for odd i values in the lookup table,
    # else we are going to search for even i values in the lookup table.
    look_up = {}
    z = 1
    if phi_approx & 1 == 1:
        for i in tqdm(range(0, b + 1), disable=(not progress)):
            if i & 1 == 1:
                look_up[z] = i
            z <<= 1
            if z >= n: z -= n
    else:
        for i in tqdm(range(0, b + 1), disable=(not progress)):
            if i & 1 == 0:
                look_up[z] = i
            z <<= 1
            if z >= n: z -= n

    # check the table
    mu = invmod(powmod(2, phi_approx, n), n)
    fac = powmod(2, b, n)

    for i in tqdm(range(0, (b * b) + 1), disable=(not progress)):
        if mu in look_up:
            phi = phi_approx + look_up[mu] - (i * b)
            r = trivial_factorization_with_n_phi(n, phi)
            if r is not None:
                return r
        mu = (mu * fac) % n


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
